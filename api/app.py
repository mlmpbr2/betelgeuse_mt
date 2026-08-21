"""
Betelgeuse TI - Multitenant API
Flask app para Vercel - Cada cliente conecta sua própria página do Facebook
Versão: 2026-08-19 - Dashboard por post, primeira importação e billing transparente
"""

import os
import re
import json
import base64
import hashlib
import hmac
import requests
import psycopg2
from datetime import datetime, timedelta
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
from flask import Flask, redirect, request, session, render_template_string, url_for, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-in-prod")

# =============================================================================
# CONFIG
# =============================================================================
FB_APP_ID = os.environ.get("FB_APP_ID", "")
FB_APP_SECRET = os.environ.get("FB_APP_SECRET", "")
FB_API_VERSION = "v25.0"
FB_BASE_URL = f"https://graph.facebook.com/{FB_API_VERSION}"
REDIRECT_URI = os.environ.get("REDIRECT_URI", "https://betelgeuse-mt.vercel.app/callback")

# Supabase
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "")

# Gemini
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Criptografia
ENCRYPTION_KEY = os.environ.get("TOKEN_SECRET", "")
if ENCRYPTION_KEY:
    # Garantir que a chave seja válida para Fernet (32 bytes, base64)
    key_bytes = ENCRYPTION_KEY.encode()[:32].ljust(32, b'0')
    FERNET_KEY = base64.urlsafe_b64encode(key_bytes)
    fernet = Fernet(FERNET_KEY)
else:
    fernet = None

# Webhook
WEBHOOK_VERIFY_TOKEN = os.environ.get("WEBHOOK_VERIFY_TOKEN", "betelgeuse_webhook_2026")
WEBHOOK_APP_SECRET = FB_APP_SECRET

# Billing
cost_env = os.environ.get("COST_PER_COMMENT_BRL", "0.20")
COST_PER_COMMENT_BRL = float(cost_env) if cost_env and cost_env.strip() else 0.20

# Primeira importação no /callback: limites menores para não travar o login.
# O histórico completo é processado nos ciclos de polling seguintes (N8N).
FIRST_IMPORT_MAX_POSTS = int(os.environ.get("FIRST_IMPORT_MAX_POSTS", "3"))
FIRST_IMPORT_MAX_COMMENTS = int(os.environ.get("FIRST_IMPORT_MAX_COMMENTS", "50"))

# Admin (relatório diário para o N8N)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

# In-memory store (Vercel-safe)
_WEBHOOK_EVENTS = deque(maxlen=100)

# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db_connection():
    """Conecta ao Supabase via psycopg2."""
    if not SUPABASE_DB_URL:
        raise Exception("SUPABASE_DB_URL não configurada")
    return psycopg2.connect(SUPABASE_DB_URL)


def set_rls_client(conn, client_id=None, is_superadmin=False):
    """Configura RLS no PostgreSQL."""
    with conn.cursor() as cur:
        if is_superadmin:
            cur.execute("SET LOCAL app.is_superadmin = 'true';")
        else:
            cur.execute("SET LOCAL app.is_superadmin = 'false';")
        if client_id:
            cur.execute("SET LOCAL app.current_client_id = %s;", (client_id,))
        else:
            cur.execute("SET LOCAL app.current_client_id = '0';")
        conn.commit()


def encrypt_token(token):
    """Criptografa token do Facebook."""
    if not fernet or not token:
        return token
    return fernet.encrypt(token.encode()).decode()


def decrypt_token(encrypted_token):
    """Descriptografa token do Facebook."""
    if not fernet or not encrypted_token:
        return encrypted_token
    try:
        return fernet.decrypt(encrypted_token.encode()).decode()
    except Exception:
        return None


def get_client_by_page_id(page_id):
    """Busca cliente pelo page_id."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, email, page_id, page_name, access_token_encrypted, 
                       api_key, n8n_webhook_url, is_active, total_comments_processed, total_cost_brl
                FROM clients WHERE page_id = %s AND is_active = TRUE
            """, (page_id,))
            row = cur.fetchone()
            if row:
                return {
                    "id": row[0], "name": row[1], "email": row[2], "page_id": row[3],
                    "page_name": row[4], "access_token_encrypted": row[5], "api_key": row[6],
                    "n8n_webhook_url": row[7], "is_active": row[8],
                    "total_comments_processed": row[9], "total_cost_brl": row[10]
                }
            return None
    finally:
        conn.close()


def get_client_by_api_key(api_key):
    """Busca cliente pela API key."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, email, page_id, page_name, access_token_encrypted,
                       api_key, n8n_webhook_url, is_active, total_comments_processed, total_cost_brl,
                       first_import_at, first_import_count, backfill_status, backfill_completed_at
                FROM clients WHERE api_key = %s AND is_active = TRUE
            """, (api_key,))
            row = cur.fetchone()
            if row:
                return {
                    "id": row[0], "name": row[1], "email": row[2], "page_id": row[3],
                    "page_name": row[4], "access_token_encrypted": row[5], "api_key": row[6],
                    "n8n_webhook_url": row[7], "is_active": row[8],
                    "total_comments_processed": row[9], "total_cost_brl": row[10],
                    "first_import_at": row[11], "first_import_count": row[12],
                    "backfill_status": row[13], "backfill_completed_at": row[14]
                }
            return None
    finally:
        conn.close()

def save_client(name, email, page_id, page_name, access_token, n8n_webhook_url=""):
    """Salva novo cliente no Supabase. Ao reconectar (conflito no page_id),
    mantém a api_key existente para não invalidar o acesso do cliente."""
    api_key = hashlib.sha256(f"{page_id}{datetime.now().isoformat()}".encode()).hexdigest()[:32]
    encrypted_token = encrypt_token(access_token)

    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO clients (name, email, page_id, page_name, access_token_encrypted, api_key, n8n_webhook_url)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (page_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    email = EXCLUDED.email,
                    page_name = EXCLUDED.page_name,
                    access_token_encrypted = EXCLUDED.access_token_encrypted,
                    n8n_webhook_url = EXCLUDED.n8n_webhook_url,
                    is_active = TRUE
                RETURNING id, api_key
            """, (name, email, page_id, page_name, encrypted_token, api_key, n8n_webhook_url))
            row = cur.fetchone()
            conn.commit()
            return {"id": row[0], "api_key": row[1]}
    finally:
        conn.close()


def save_comment(client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source="webhook", is_new=True):
    """Salva comentário no Supabase. is_new=False no backfill (histórico)."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO comments (client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source, is_new)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (client_id, comment_id) DO NOTHING
                RETURNING id
            """, (client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source, is_new))
            row = cur.fetchone()
            conn.commit()
            return row[0] if row else None
    except Exception as e:
        print(f"Error saving comment: {e}")
        return None
    finally:
        conn.close()


def save_posts(client_id, posts):
    """Upsert em lote de posts do Facebook (para agrupar comentários no dashboard)."""
    if not posts:
        return
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.executemany("""
                INSERT INTO posts (client_id, post_id, message, permalink_url, created_time)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (client_id, post_id) DO UPDATE SET
                    message = EXCLUDED.message,
                    permalink_url = EXCLUDED.permalink_url
            """, [(client_id, p.get("id"), p.get("message", ""),
                   p.get("permalink_url", ""), p.get("created_time")) for p in posts])
            conn.commit()
    except Exception as e:
        print(f"Error saving posts: {e}")
    finally:
        conn.close()


def mark_first_import(client_id, comments_count):
    """Registra a primeira importação do cliente (só na primeira vez)."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE clients
                SET first_import_at = COALESCE(first_import_at, NOW()),
                    first_import_count = GREATEST(COALESCE(first_import_count, 0), %s)
                WHERE id = %s
            """, (comments_count, client_id))
            conn.commit()
    except Exception as e:
        print(f"Error marking first import: {e}")
    finally:
        conn.close()


def save_poll_log(client_id, posts_checked, comments_found, comments_new, comments_analyzed, cost_brl, error_message="", triggered_by="api"):
    """Salva log de polling."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO poll_logs (client_id, posts_checked, comments_found, comments_new, comments_analyzed, cost_brl, error_message, triggered_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (client_id, posts_checked, comments_found, comments_new, comments_analyzed, cost_brl, error_message, triggered_by))
            conn.commit()
    except Exception as e:
        print(f"Error saving poll log: {e}")
    finally:
        conn.close()


def update_client_stats(client_id, comments_count, cost_brl):
    """Atualiza estatísticas do cliente."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE clients 
                SET total_comments_processed = total_comments_processed + %s,
                    total_cost_brl = total_cost_brl + %s,
                    last_poll_at = NOW()
                WHERE id = %s
            """, (comments_count, cost_brl, client_id))
            conn.commit()
    except Exception as e:
        print(f"Error updating client stats: {e}")
    finally:
        conn.close()


def get_client_comments(client_id, limit=100, sentiment_filter=None):
    """Busca comentários do cliente."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            if sentiment_filter:
                cur.execute("""
                    SELECT comment_id, post_id, author_name, message, sentiment, like_count, created_time, analyzed_at, is_new, source
                    FROM comments WHERE client_id = %s AND sentiment = %s
                    ORDER BY created_time DESC LIMIT %s
                """, (client_id, sentiment_filter, limit))
            else:
                cur.execute("""
                    SELECT comment_id, post_id, author_name, message, sentiment, like_count, created_time, analyzed_at, is_new, source
                    FROM comments WHERE client_id = %s
                    ORDER BY created_time DESC LIMIT %s
                """, (client_id, limit))
            rows = cur.fetchall()
            return [{
                "comment_id": r[0], "post_id": r[1], "author_name": r[2], "message": r[3],
                "sentiment": r[4], "like_count": r[5], "created_time": r[6],
                "analyzed_at": r[7], "is_new": r[8], "source": r[9]
            } for r in rows]
    finally:
        conn.close()


def get_client_posts_with_comments(client_id, limit_posts=20, comments_per_post=100):
    """Posts do cliente com comentários agrupados. Retorna (posts, outros_comentarios)."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT post_id, message, permalink_url, created_time
                FROM posts WHERE client_id = %s
                ORDER BY created_time DESC NULLS LAST LIMIT %s
            """, (client_id, limit_posts))
            posts = [{
                "post_id": r[0], "message": r[1] or "", "permalink_url": r[2] or "",
                "created_time": r[3], "comments": []
            } for r in cur.fetchall()]
            post_map = {p["post_id"]: p for p in posts}

            cur.execute("""
                SELECT comment_id, post_id, author_name, message, sentiment, like_count, created_time
                FROM comments WHERE client_id = %s
                ORDER BY created_time DESC LIMIT 500
            """, (client_id,))
            others = []
            for r in cur.fetchall():
                comment = {
                    "comment_id": r[0], "post_id": r[1], "author_name": r[2],
                    "message": r[3], "sentiment": r[4], "like_count": r[5], "created_time": r[6]
                }
                p = post_map.get(r[1])
                if p is None:
                    others.append(comment)
                elif len(p["comments"]) < comments_per_post:
                    p["comments"].append(comment)

            for p in posts:
                counts = {"POSITIVO": 0, "NEUTRO": 0, "NEGATIVO": 0}
                for c in p["comments"]:
                    if c["sentiment"] in counts:
                        counts[c["sentiment"]] += 1
                p["counts"] = counts
            return posts, others
    finally:
        conn.close()


def update_backfill_state(client_id, status, cursor=None, completed=False):
    """Atualiza o checkpoint do backfill do cliente."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            if completed:
                cur.execute("""
                    UPDATE clients
                    SET backfill_status = %s, backfill_cursor = NULL, backfill_completed_at = NOW()
                    WHERE id = %s
                """, (status, client_id))
            elif cursor is not None:
                cur.execute("""
                    UPDATE clients SET backfill_status = %s, backfill_cursor = %s WHERE id = %s
                """, (status, cursor, client_id))
            else:
                cur.execute("""
                    UPDATE clients SET backfill_status = %s WHERE id = %s
                """, (status, client_id))
            conn.commit()
    except Exception as e:
        print(f"Error updating backfill state: {e}")
    finally:
        conn.close()


def get_client_billing(client_id):
    """Billing do cliente: (resumo mensal, últimos poll_logs)."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT to_char(analyzed_at, 'YYYY-MM') AS mes, COUNT(*) AS qtd
                FROM comments
                WHERE client_id = %s AND analyzed_at IS NOT NULL
                GROUP BY 1 ORDER BY 1 DESC
            """, (client_id,))
            monthly = [{"mes": r[0], "qtd": r[1], "custo": float(r[1]) * COST_PER_COMMENT_BRL}
                       for r in cur.fetchall()]

            cur.execute("""
                SELECT polled_at, posts_checked, comments_found, comments_new,
                       comments_analyzed, cost_brl, triggered_by
                FROM poll_logs WHERE client_id = %s
                ORDER BY polled_at DESC LIMIT 30
            """, (client_id,))
            polls = [{
                "polled_at": r[0], "posts_checked": r[1], "comments_found": r[2],
                "comments_new": r[3], "comments_analyzed": r[4],
                "cost_brl": float(r[5] or 0), "triggered_by": r[6]
            } for r in cur.fetchall()]
            return monthly, polls
    finally:
        conn.close()


def get_client_daily_usage(client_id, days=30):
    """Uso por dia do cliente (view daily_usage), com custo calculado."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT day, comments_analyzed
                FROM daily_usage
                WHERE client_id = %s AND day >= CURRENT_DATE - %s
                ORDER BY day DESC
            """, (client_id, days))
            return [{
                "day": r[0].isoformat() if r[0] else None,
                "comments_analyzed": r[1],
                "cost_brl": round(float(r[1]) * COST_PER_COMMENT_BRL, 2)
            } for r in cur.fetchall()]
    finally:
        conn.close()


# =============================================================================
# FACEBOOK API HELPERS
# =============================================================================

def fb_get(url_path, params, access_token):
    """Graph API GET."""
    try:
        resp = requests.get(
            f"{FB_BASE_URL}/{url_path}",
            params={**params, "access_token": access_token},
            timeout=30
        )
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def fb_get_paginated(url_path, params, access_token, max_items=200):
    """Paginated GET."""
    items = []
    url = f"{FB_BASE_URL}/{url_path}"
    next_params = {**params, "access_token": access_token}
    try:
        while len(items) < max_items:
            resp = requests.get(url, params=next_params, timeout=30)
            data = resp.json()
            if "error" in data:
                return items, data["error"].get("message", str(data["error"]))
            batch = data.get("data", [])
            if not batch:
                return items, None
            items.extend(batch)
            next_url = data.get("paging", {}).get("next")
            if not next_url:
                return items, None
            url = next_url
            next_params = {}
        return items[:max_items], None
    except Exception as e:
        return items, str(e)


def get_page_token(user_token, page_id):
    """Pega Page Access Token do usuário."""
    try:
        resp = requests.get(
            f"{FB_BASE_URL}/me/accounts",
            params={"access_token": user_token},
            timeout=30
        )
        for acc in resp.json().get("data", []):
            if acc.get("id") == page_id:
                return acc.get("access_token")
    except Exception as e:
        print(f"Error fetching page token: {e}")
    return None

# =============================================================================
# SENTIMENT ANALYSIS (Gemini)
# =============================================================================

BATCH_SIZE = 20


def analyze_sentiment(text):
    """Analisa sentimento de um comentário."""
    if not GOOGLE_API_KEY or not text:
        print(f"[SENTIMENT] SKIP - no API key or empty text")
        return "NEUTRO"
    try:
        url = f"{GEMINI_URL}?key={GOOGLE_API_KEY}"
        prompt = f"Classifique o sentimento deste comentario em UMA palavra apenas: POSITIVO, NEUTRO ou NEGATIVO. Comentario: {text}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 100,
                "thinkingConfig": {"thinkingLevel": "minimal"}
            }
        }
        resp = requests.post(url, json=payload, timeout=30)
        data = resp.json()
        print(f"[SENTIMENT] API status={resp.status_code}, response={json.dumps(data)[:300]}")

        if "candidates" in data and data["candidates"]:
            candidate = data["candidates"][0]
            finish = candidate.get("finishReason", "?")
            parts = candidate.get("content", {}).get("parts", [])
            result = "".join(p.get("text", "") for p in parts if isinstance(p, dict)).upper().strip()
            print(f"[SENTIMENT] finishReason={finish}, raw result: '{result}'")
            if not result:
                print(f"[SENTIMENT] Empty content from API (finishReason={finish})")
                return "NEUTRO"
            if "POSITIVO" in result:
                return "POSITIVO"
            elif "NEGATIVO" in result:
                return "NEGATIVO"
            else:
                print(f"[SENTIMENT] Fallback to NEUTRO - result was: '{result}'")
                return "NEUTRO"
        elif "error" in data:
            print(f"[SENTIMENT] API ERROR: {data['error']}")
            return "NEUTRO"
        else:
            print(f"[SENTIMENT] No candidates in response: {json.dumps(data)[:200]}")
            return "NEUTRO"
    except Exception as e:
        print(f"[SENTIMENT] Exception: {e}")
        return "NEUTRO"


def analyze_sentiments_batch(texts):
    """Analisa batch de sentimentos."""
    if not texts or not GOOGLE_API_KEY:
        print(f"[SENTIMENT-BATCH] SKIP - no texts or no API key")
        return ["NEUTRO"] * len(texts)
    try:
        numbered = "\n".join(f"{i+1}. {t[:280].replace(chr(10), ' ')}" for i, t in enumerate(texts))
        prompt = (
            "Classifique o sentimento de cada comentario em UMA palavra: POSITIVO, NEUTRO ou NEGATIVO.\n"
            "Responda APENAS um JSON array de strings, na MESMA ORDEM, sem explicacoes.\n"
            'Exemplo: ["POSITIVO","NEUTRO","NEGATIVO"]\n\n'
            f"Comentarios:\n{numbered}"
        )
        url = f"{GEMINI_URL}?key={GOOGLE_API_KEY}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
                "thinkingConfig": {"thinkingLevel": "minimal"}
            }
        }
        resp = requests.post(url, json=payload, timeout=60)
        data = resp.json()
        print(f"[SENTIMENT-BATCH] API status={resp.status_code}")

        if "error" in data:
            print(f"[SENTIMENT-BATCH] API ERROR: {data['error']}")
            return ["NEUTRO"] * len(texts)

        if "candidates" not in data or not data["candidates"]:
            print(f"[SENTIMENT-BATCH] No candidates: {json.dumps(data)[:200]}")
            return ["NEUTRO"] * len(texts)

        candidate = data["candidates"][0]
        finish = candidate.get("finishReason", "?")
        parts = candidate.get("content", {}).get("parts", [])
        result_text = "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()
        print(f"[SENTIMENT-BATCH] finishReason={finish}, raw result: {result_text[:300]}")

        if not result_text:
            print(f"[SENTIMENT-BATCH] Empty content from API (finishReason={finish})")
            return ["NEUTRO"] * len(texts)

        # Tenta parsear como JSON direto primeiro
        try:
            arr = json.loads(result_text)
            if isinstance(arr, list):
                sentiments = []
                for item in arr[:len(texts)]:
                    s = str(item).upper().strip()
                    if "POSITIVO" in s:
                        sentiments.append("POSITIVO")
                    elif "NEGATIVO" in s:
                        sentiments.append("NEGATIVO")
                    else:
                        sentiments.append("NEUTRO")
                while len(sentiments) < len(texts):
                    sentiments.append("NEUTRO")
                print(f"[SENTIMENT-BATCH] Parsed {len(sentiments)} sentiments: {sentiments}")
                return sentiments
        except json.JSONDecodeError:
            pass

        # Fallback: procura array JSON no texto
        match = re.search(r"\[.*\]", result_text, re.DOTALL)
        if match:
            try:
                arr = json.loads(match.group(0))
                sentiments = []
                for item in arr[:len(texts)]:
                    s = str(item).upper().strip()
                    if "POSITIVO" in s:
                        sentiments.append("POSITIVO")
                    elif "NEGATIVO" in s:
                        sentiments.append("NEGATIVO")
                    else:
                        sentiments.append("NEUTRO")
                while len(sentiments) < len(texts):
                    sentiments.append("NEUTRO")
                print(f"[SENTIMENT-BATCH] Regex parsed {len(sentiments)} sentiments")
                return sentiments
            except json.JSONDecodeError as e:
                print(f"[SENTIMENT-BATCH] JSON parse error: {e}")

        print(f"[SENTIMENT-BATCH] Could not parse response, falling back to individual")
        # Fallback: analisa um por um
        return [analyze_sentiment(t) for t in texts]

    except Exception as e:
        print(f"[SENTIMENT-BATCH] Exception: {e}")
        return ["NEUTRO"] * len(texts)


def analyze_many(texts):
    """Processa em batches paralelos."""
    if not texts:
        return []
    batches = [texts[i:i + BATCH_SIZE] for i in range(0, len(texts), BATCH_SIZE)]
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for batch_result in executor.map(analyze_sentiments_batch, batches):
            results.extend(batch_result)
    return results


def analyze_and_update_comments(client_id, new_comments):
    """Analisa sentimento dos comentários novos e atualiza no banco.
    Retorna a lista de sentimentos (mesma ordem de new_comments)."""
    if not new_comments:
        return []
    texts = [c["message"] for c in new_comments]
    sentiments = analyze_many(texts)

    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            for nc, sentiment in zip(new_comments, sentiments):
                cur.execute("""
                    UPDATE comments SET sentiment = %s, analyzed_at = NOW()
                    WHERE client_id = %s AND comment_id = %s
                """, (sentiment, client_id, nc["id"]))
            conn.commit()
    finally:
        conn.close()
    return sentiments

# =============================================================================
# WEBHOOK SECURITY
# =============================================================================

def verify_signature(payload_body, signature_header):
    if not WEBHOOK_APP_SECRET:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(
        WEBHOOK_APP_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    received = signature_header.split("sha256=", 1)[1]
    return hmac.compare_digest(expected, received)


def extract_webhook_comment_info(payload):
    """Extrai info de comentário do payload do webhook."""
    entries = payload.get("entry", [])
    if not entries:
        return None
    entry = entries[0]
    changes = entry.get("changes", [])
    if not changes:
        return None
    change = changes[0]
    value = change.get("value", {})
    return {
        "page_id": entry.get("id", ""),
        "field": change.get("field", ""),
        "item": value.get("item", ""),
        "verb": value.get("verb", ""),
        "comment_id": value.get("comment_id", ""),
        "post_id": value.get("post_id", ""),
        "message": value.get("message", "")[:500],
        "author_name": value.get("from", {}).get("name", "") if isinstance(value.get("from"), dict) else "",
        "author_id": value.get("from", {}).get("id", "") if isinstance(value.get("from"), dict) else "",
        "created_time": value.get("created_time", datetime.now().isoformat()),
    }


# =============================================================================
# HTML TEMPLATES
# =============================================================================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Betelgeuse TI - Multitenant</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #1c1e21; line-height: 1.5; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 20px; text-align: center; border-bottom: 3px solid #1877f2; }
        .header h1 { font-size: 24px; margin-bottom: 4px; }
        .header p { color: #b0b3b8; font-size: 14px; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
        .card-desc { color: #65676b; font-size: 14px; margin-bottom: 16px; }
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 24px; border-radius: 8px; border: none; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; transition: all 0.2s; }
        .btn-primary { background: #1877f2; color: white; }
        .btn-primary:hover { background: #166fe5; }
        .btn-success { background: #2e7d32; color: white; }
        .btn-outline { background: white; color: #1877f2; border: 1px solid #1877f2; font-size: 13px; padding: 6px 14px; }
        .alert { padding: 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .alert-info { background: #e3f2fd; color: #1565c0; border: 1px solid #bbdefb; }
        .alert-warning { background: #fff8e1; color: #f57f17; border: 1px solid #ffe082; }
        .footer { text-align: center; padding: 40px 20px; color: #65676b; font-size: 13px; }
        .code-box { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
        .stat-box { background: white; border-radius: 12px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-top: 3px solid #1877f2; }
        .stat-value { font-size: 28px; font-weight: 700; color: #1877f2; }
        .stat-label { font-size: 12px; color: #65676b; text-transform: uppercase; }
        .comment-card { background: #f8f9fa; border-radius: 12px; padding: 16px; margin-bottom: 12px; border-left: 4px solid #1877f2; }
        .comment-card.positive, .comment-card.positivo { border-left-color: #2e7d32; background: #e8f5e9; }
        .comment-card.neutral, .comment-card.neutro { border-left-color: #f9a825; background: #fff8e1; }
        .comment-card.negative, .comment-card.negativo { border-left-color: #c62828; background: #ffebee; }
        .sentiment-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .sentiment-positive, .sentiment-positivo { background: #2e7d32; color: white; }
        .sentiment-neutral, .sentiment-neutro { background: #f9a825; color: white; }
        .sentiment-negative, .sentiment-negativo { background: #c62828; color: white; }
        table.data-table { width: 100%; border-collapse: collapse; font-size: 14px; }
        table.data-table th { text-align: left; padding: 8px; border-bottom: 2px solid #ddd; color: #65676b; font-size: 12px; text-transform: uppercase; }
        table.data-table td { padding: 8px; border-bottom: 1px solid #eee; }
        input, select { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid #ddd; font-size: 15px; background: white; margin-bottom: 12px; }
        label { font-size: 13px; font-weight: 600; color: #65676b; display: block; margin-bottom: 4px; }
        .form-group { margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌟 Betelgeuse TI</h1>
        <p>MONITORAMENTO MULTITENANT DE COMENTÁRIOS</p>
    </div>
    <div class="container">
        {{ content | safe }}
    </div>
    <div class="footer">
        <p>© 2026 Betelgeuse IT Services - CNPJ 51.770.124/0001-97</p>
    </div>
</body>
</html>
"""

HOME_TEMPLATE = """
<div class="card" style="text-align: center; max-width: 600px; margin: 40px auto;">
    <h2 style="font-size: 22px; margin-bottom: 12px;">Conecte sua Página do Facebook</h2>
    <p style="color: #65676b; margin-bottom: 24px;">
        Monitore e analise os comentários da sua página em tempo real com IA.
        Cada cliente gerencia sua própria página — você nunca precisa ser admin.
    </p>
    <a href="/login" class="btn btn-primary" style="font-size: 16px;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>
        Conectar com Facebook
    </a>
    <div style="margin-top: 24px; text-align: left; background: #f8f9fa; padding: 16px; border-radius: 8px;">
        <h3 style="font-size: 14px; margin-bottom: 8px;">🔒 Como funciona:</h3>
        <ul style="font-size: 13px; color: #65676b; line-height: 2; list-style: none;">
            <li>✓ Você autoriza o app na sua própria página</li>
            <li>✓ Seu token é criptografado e armazenado com segurança</li>
            <li>✓ Comentários são analisados automaticamente por IA</li>
            <li>✓ Você recebe alertas em tempo real</li>
        </ul>
    </div>
</div>
"""

SUCCESS_TEMPLATE = """
<div class="card" style="text-align: center; max-width: 600px; margin: 40px auto;">
    <div class="alert alert-success">
        ✅ <strong>Página conectada com sucesso!</strong>
    </div>
    <h2 style="font-size: 20px; margin-bottom: 12px;">{{ page_name }}</h2>
    <p style="color: #65676b; margin-bottom: 16px;">Page ID: {{ page_id }}</p>

    {% if import_info %}
    <div class="alert alert-info" style="text-align: left;">
        📥 <strong>Primeira sincronização concluída:</strong>
        {{ import_info.comments_new }} comentários importados de {{ import_info.posts_checked }} posts
        — custo: R$ {{ "%.2f"|format(import_info.cost_brl) }}
    </div>
    {% else %}
    <div class="alert alert-info" style="text-align: left;">
        🔄 <strong>Sincronização automática ativa</strong> — os comentários serão processados
        automaticamente nos próximos ciclos (a cada hora).
    </div>
    {% endif %}

    <div style="background: #f8f9fa; padding: 16px; border-radius: 8px; text-align: left; margin-bottom: 20px;">
        <h3 style="font-size: 14px; margin-bottom: 8px;">🔑 Sua API Key:</h3>
        <div class="code-box">{{ api_key }}</div>
        <p style="font-size: 12px; color: #65676b; margin-top: 8px;">Guarde essa chave! Ela é usada para acessar seus dados.</p>
    </div>

    <a href="/client/{{ api_key }}/dashboard" class="btn btn-success">📊 Ver Dashboard</a>
</div>
"""

CLIENT_DASHBOARD_TEMPLATE = """
<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
            <h2 style="font-size: 20px;">{{ client.name }}</h2>
            <p style="color: #65676b; font-size: 13px;">{{ client.page_name }} | Page ID: {{ client.page_id }}</p>
            {% if client.first_import_at %}
            <p style="color: #65676b; font-size: 12px; margin-top: 4px;">
                📥 Primeira importação: <strong>{{ client.first_import_count }} comentários</strong> em
                {% if client.first_import_at is string %}
                    {{ client.first_import_at[:10] }}
                {% else %}
                    {{ client.first_import_at.strftime('%d/%m/%Y') }}
                {% endif %}
            </p>
            {% endif %}
        </div>
        <div style="text-align: right;">
            <p style="font-size: 12px; color: #65676b;">Comentários processados</p>
            <p style="font-size: 24px; font-weight: 700; color: #1877f2;">{{ client.total_comments_processed }}</p>
            <a href="/client/{{ client.api_key }}/billing" class="btn btn-outline" style="margin-top: 8px;">💰 Meu faturamento</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-box" style="border-top-color: #2e7d32;">
            <div class="stat-value" style="color: #2e7d32;">{{ sentiment_counts.POSITIVO }}</div>
            <div class="stat-label">😊 Positivos</div>
        </div>
        <div class="stat-box" style="border-top-color: #f9a825;">
            <div class="stat-value" style="color: #f9a825;">{{ sentiment_counts.NEUTRO }}</div>
            <div class="stat-label">😐 Neutros</div>
        </div>
        <div class="stat-box" style="border-top-color: #c62828;">
            <div class="stat-value" style="color: #c62828;">{{ sentiment_counts.NEGATIVO }}</div>
            <div class="stat-label">😠 Negativos</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">R$ {{ "%.2f"|format(client.total_cost_brl) }}</div>
            <div class="stat-label">💰 Custo Total</div>
        </div>
    </div>
</div>

{% for post in posts %}
<div class="card">
    <div style="margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #eee;">
        <p style="font-size: 14px; font-weight: 600;">
            📝 {{ post.message[:200] if post.message else '(Post sem texto)' }}{% if post.message|length > 200 %}...{% endif %}
        </p>
        <div style="font-size: 12px; color: #65676b; margin-top: 4px;">
            {% if post.created_time %}
                {% if post.created_time is string %}
                    📅 {{ post.created_time[:10] }} |
                {% else %}
                    📅 {{ post.created_time.strftime('%d/%m/%Y') }} |
                {% endif %}
            {% endif %}
            💬 {{ post.comments|length }} comentários
            (😊 {{ post.counts.POSITIVO }} · 😐 {{ post.counts.NEUTRO }} · 😠 {{ post.counts.NEGATIVO }})
            {% if post.permalink_url %}
                | <a href="{{ post.permalink_url }}" target="_blank" style="color: #1877f2;">Ver no Facebook ↗</a>
            {% endif %}
        </div>
    </div>
    {% for comment in post.comments %}
    <div class="comment-card {{ comment.sentiment|lower }}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="font-size: 14px;">{{ comment.author_name or 'Usuário' }}</strong>
            <span class="sentiment-badge sentiment-{{ comment.sentiment|lower }}">{{ comment.sentiment }}</span>
        </div>
        <p style="font-size: 14px; margin-bottom: 8px;">{{ comment.message }}</p>
        <div style="font-size: 12px; color: #65676b;">
            {% if comment.created_time %}
                {% if comment.created_time is string %}
                    📅 {{ comment.created_time[:10] }} |
                {% else %}
                    📅 {{ comment.created_time.strftime('%Y-%m-%d') }} |
                {% endif %}
            {% endif %}
            ❤️ {{ comment.like_count }} likes
        </div>
    </div>
    {% else %}
    <p style="color: #65676b; font-size: 13px;">Nenhum comentário neste post ainda.</p>
    {% endfor %}
</div>
{% else %}
<div class="card">
    <p style="color: #65676b; text-align: center; padding: 20px;">
        Nenhum post sincronizado ainda. A primeira sincronização acontece automaticamente no próximo ciclo (em até 1 hora).
    </p>
</div>
{% endfor %}

{% if other_comments %}
<div class="card">
    <div class="card-title">💬 Outros comentários</div>
    <p class="card-desc">Comentários recebidos em tempo real, antes da sincronização do post.</p>
    {% for comment in other_comments %}
    <div class="comment-card {{ comment.sentiment|lower }}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="font-size: 14px;">{{ comment.author_name or 'Usuário' }}</strong>
            <span class="sentiment-badge sentiment-{{ comment.sentiment|lower }}">{{ comment.sentiment }}</span>
        </div>
        <p style="font-size: 14px; margin-bottom: 8px;">{{ comment.message }}</p>
        <div style="font-size: 12px; color: #65676b;">
            {% if comment.created_time %}
                {% if comment.created_time is string %}
                    📅 {{ comment.created_time[:10] }} |
                {% else %}
                    📅 {{ comment.created_time.strftime('%Y-%m-%d') }} |
                {% endif %}
            {% endif %}
            📝 Post: {{ comment.post_id }}
        </div>
    </div>
    {% endfor %}
</div>
{% endif %}
"""

BILLING_TEMPLATE = """
<style>
@media print {
    .header, .footer, .no-print { display: none !important; }
    body { background: white; }
    .card { box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; }
}
</style>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h2 style="font-size: 20px;">💰 Faturamento — {{ client.name }}</h2>
            <p style="color: #65676b; font-size: 13px;">{{ client.page_name }} | Page ID: {{ client.page_id }}</p>
        </div>
        <button onclick="window.print()" class="btn btn-primary no-print">🖨️ Salvar como PDF / Imprimir</button>
    </div>
</div>

<div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
    <div class="stat-box">
        <div class="stat-value">{{ total_analyzed }}</div>
        <div class="stat-label">💬 Comentários analisados</div>
    </div>
    <div class="stat-box">
        <div class="stat-value">R$ {{ "%.2f"|format(client.total_cost_brl) }}</div>
        <div class="stat-label">💰 Custo total</div>
    </div>
    <div class="stat-box" style="border-top-color: #2e7d32;">
        <div class="stat-value" style="color: #2e7d32;">R$ {{ "%.2f"|format(current.custo) }}</div>
        <div class="stat-label">📅 Mês atual ({{ current.qtd }} comentários)</div>
    </div>
</div>

<div class="card">
    <div class="card-title">📅 Detalhamento mensal</div>
    <p class="card-desc">
        Você paga <strong>R$ {{ "%.2f"|format(price) }} por comentário analisado</strong>.
        Apenas comentários NOVOS são cobrados — sincronizações sem novidades custam R$ 0,00.
    </p>
    <table class="data-table">
        <thead>
            <tr><th>Mês</th><th>Comentários</th><th>R$/comentário</th><th>Total</th></tr>
        </thead>
        <tbody>
            {% for m in monthly %}
            <tr>
                <td>{{ m.mes_label }}</td>
                <td>{{ m.qtd }}</td>
                <td>R$ {{ "%.2f"|format(price) }}</td>
                <td><strong>R$ {{ "%.2f"|format(m.custo) }}</strong></td>
            </tr>
            {% else %}
            <tr><td colspan="4" style="text-align: center; color: #65676b; padding: 16px;">Nenhum comentário analisado ainda.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div class="card">
    <div class="card-title">ℹ️ Como calculamos</div>
    <p style="font-size: 14px; color: #444; line-height: 1.8;">
        O valor de <strong>R$ {{ "%.2f"|format(price) }} por comentário</strong> cobre a infraestrutura de
        automação (N8N), a análise de sentimento por IA (Google Gemini), o banco de dados e a
        manutenção e evolução da plataforma. Sua página tem <strong>volume alto de comentários</strong>?
        Fale conosco — oferecemos condições especiais por volume.
    </p>
</div>

<div class="card">
    <div class="card-title">🔄 Histórico de sincronizações</div>
    <p class="card-desc">Cada linha é um ciclo de verificação da sua página (a cada hora). Custo só existe quando há comentários novos.</p>
    <table class="data-table">
        <thead>
            <tr><th>Data</th><th>Origem</th><th>Posts</th><th>Novos</th><th>Analisados</th><th>Custo</th></tr>
        </thead>
        <tbody>
            {% for p in polls %}
            <tr>
                <td>
                    {% if p.polled_at is string %}
                        {{ p.polled_at[:16] }}
                    {% else %}
                        {{ p.polled_at.strftime('%d/%m/%Y %H:%M') }}
                    {% endif %}
                </td>
                <td>{{ p.origem_label }}</td>
                <td>{{ p.posts_checked }}</td>
                <td>{{ p.comments_new }}</td>
                <td>{{ p.comments_analyzed }}</td>
                <td>R$ {{ "%.2f"|format(p.cost_brl) }}</td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="text-align: center; color: #65676b; padding: 16px;">Nenhuma sincronização registrada ainda.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div style="text-align: center; margin-bottom: 20px;" class="no-print">
    <a href="/client/{{ client.api_key }}/dashboard" class="btn btn-outline">← Voltar ao dashboard</a>
</div>
"""


# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route("/")
def home():
    return render_template_string(BASE_TEMPLATE, content=HOME_TEMPLATE)


@app.route("/login")
def login():
    scopes = "pages_show_list,pages_read_engagement,pages_read_user_content,pages_manage_metadata"
    auth_url = (
        f"https://www.facebook.com/{FB_API_VERSION}/dialog/oauth"
        f"?client_id={FB_APP_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={scopes}"
        f"&response_type=code"
        f"&auth_type=reauthenticate"  # ← Seletor de Pg.
    )
    return redirect(auth_url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Erro: Código não fornecido", 400

    # Troca code por token
    token_url = f"{FB_BASE_URL}/oauth/access_token"
    params = {
        "client_id": FB_APP_ID,
        "client_secret": FB_APP_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code
    }
    try:
        resp = requests.get(token_url, params=params, timeout=30)
        data = resp.json()
        if "access_token" not in data:
            return f"Erro na autenticação: {data}", 400

        user_token = data["access_token"]

        # Pega informações do usuário
        me_data = fb_get("me", {"fields": "id,name,email"}, user_token)
        user_name = me_data.get("name", "")
        user_email = me_data.get("email", "")

        # Pega páginas do usuário
        pages_resp = requests.get(
            f"{FB_BASE_URL}/me/accounts",
            params={"access_token": user_token, "fields": "id,name,access_token"},
            timeout=30
        )
        pages = pages_resp.json().get("data", [])

        if not pages:
            return render_template_string(BASE_TEMPLATE, content="""
                <div class="card" style="text-align: center;">
                    <div class="alert alert-warning">
                        ⚠️ Você não possui páginas do Facebook. Crie uma página primeiro.
                    </div>
                </div>
            """)

        # 🔄 ITERA SOBRE TODAS AS PÁGINAS (não só a primeira!)
        connected_pages = []
        for page in pages:
            page_id = page["id"]
            page_name = page["name"]
            page_token = page.get("access_token", user_token)

            # Salva no Supabase
            result = save_client(user_name, user_email, page_id, page_name, page_token)

            # Primeira importação: baixa comentários históricos
            import_info = None
            try:
                first_client = {
                    "id": result["id"], "page_id": page_id,
                    "page_name": page_name, "n8n_webhook_url": ""
                }
                import_info = run_poll_for_client(
                    first_client, page_token,
                    triggered_by="first_import", source="first_import",
                    max_posts=FIRST_IMPORT_MAX_POSTS,
                    max_comments=FIRST_IMPORT_MAX_COMMENTS
                )
                mark_first_import(result["id"], import_info["comments_new"])
            except Exception as e:
                print(f"[FIRST-IMPORT] Erro em {page_name} (não bloqueia): {e}")
                import_info = None

            connected_pages.append({
                "page_name": page_name,
                "page_id": page_id,
                "api_key": result["api_key"],
                "import_info": import_info
            })

        # Renderiza sucesso com TODAS as páginas
        content = f"""
        <div class="card" style="text-align: center;">
            <div class="alert alert-success">
                ✅ <strong>{len(connected_pages)} página(s) conectada(s) com sucesso!</strong>
            </div>
        </div>
        """
        for p in connected_pages:
            if p["import_info"]:
                import_html = f"""
                <div style="background: #e3f2fd; border-radius: 8px; padding: 12px; margin: 12px 0;">
                    📥 <strong>Sincronização inicial:</strong> {p['import_info']['comments_new']} comentários importados de {p['import_info']['posts_checked']} posts — custo: R$ {p['import_info']['cost_brl']:.2f}<br>
                    <span style="font-size: 12px; color: #1565c0;">Esta é uma importação inicial parcial. O histórico completo é processado automaticamente nos próximos ciclos (a cada hora).</span>
                </div>
                """
            else:
                import_html = """
                <div style="background: #e3f2fd; border-radius: 8px; padding: 12px; margin: 12px 0;">
                    🔄 <strong>Sincronização automática ativa</strong> — os comentários serão processados automaticamente nos próximos ciclos (a cada hora).
                </div>
                """
            content += f"""
            <div class="card" style="margin-bottom: 16px;">
                <h3>📄 {p['page_name']}</h3>
                <p style="color: #65676b; font-size: 13px;">Page ID: {p['page_id']}</p>
                {import_html}
                <div style="background: #1a1a2e; color: white; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 13px; margin: 12px 0;">
                    🔑 API Key: {p['api_key']}
                </div>
                <a href="/client/{p['api_key']}/dashboard" class="btn btn-primary">📊 Ver Dashboard</a>
            </div>
            """
        
        return render_template_string(BASE_TEMPLATE, content=content)

    except Exception as e:
        return f"Erro: {str(e)}", 500

@app.route("/client/<api_key>/dashboard")
def client_dashboard(api_key):
    client = get_client_by_api_key(api_key)
    if not client:
        return "Cliente não encontrado", 404

    posts, other_comments = get_client_posts_with_comments(client["id"])
    sentiment_counts = {"POSITIVO": 0, "NEUTRO": 0, "NEGATIVO": 0}
    for p in posts:
        for c in p["comments"]:
            if c["sentiment"] in sentiment_counts:
                sentiment_counts[c["sentiment"]] += 1
    for c in other_comments:
        if c["sentiment"] in sentiment_counts:
            sentiment_counts[c["sentiment"]] += 1

    content = render_template_string(CLIENT_DASHBOARD_TEMPLATE,
        client=client,
        posts=posts,
        other_comments=other_comments,
        sentiment_counts=sentiment_counts
    )
    return render_template_string(BASE_TEMPLATE, content=content)


MESES_PT = ["", "jan", "fev", "mar", "abr", "mai", "jun",
            "jul", "ago", "set", "out", "nov", "dez"]


@app.route("/client/<api_key>/billing")
def client_billing(api_key):
    """Página de faturamento transparente do cliente (imprimível em PDF)."""
    client = get_client_by_api_key(api_key)
    if not client:
        return "Cliente não encontrado", 404

    monthly, polls = get_client_billing(client["id"])

    for m in monthly:
        year, month = m["mes"].split("-")
        m["mes_label"] = f"{MESES_PT[int(month)]}/{year}"

    origem_labels = {
        "first_import": "📥 Primeira importação",
        "n8n": "🤖 Automático (N8N)",
        "api": "🔌 API"
    }
    for p in polls:
        p["origem_label"] = origem_labels.get(p["triggered_by"], p["triggered_by"])

    current_month = datetime.now().strftime("%Y-%m")
    current = next((m for m in monthly if m["mes"] == current_month),
                   {"qtd": 0, "custo": 0.0})
    total_analyzed = sum(m["qtd"] for m in monthly)

    content = render_template_string(BILLING_TEMPLATE,
        client=client,
        monthly=monthly,
        polls=polls,
        current=current,
        total_analyzed=total_analyzed,
        price=COST_PER_COMMENT_BRL
    )
    return render_template_string(BASE_TEMPLATE, content=content)


@app.route("/client/<api_key>/comments")
def client_comments_json(api_key):
    """API JSON para comentários do cliente."""
    client = get_client_by_api_key(api_key)
    if not client:
        return jsonify({"error": "Cliente não encontrado"}), 404

    sentiment_filter = request.args.get("sentiment")
    limit = int(request.args.get("limit", 100))
    comments = get_client_comments(client["id"], limit=limit, sentiment_filter=sentiment_filter)
    return jsonify({
        "client": {"id": client["id"], "name": client["name"], "page_name": client["page_name"]},
        "comments": comments,
        "total": len(comments)
    })


# =============================================================================
# POLLING (N8N chama este endpoint)
# =============================================================================

def run_poll_for_client(client, access_token, triggered_by="n8n", source="polling",
                        max_posts=10, max_comments=200):
    """Busca posts e comentários do Facebook, salva, analisa sentimento dos
    comentários novos, cobra e registra log. Usado pelo /poll (N8N) e pela
    primeira importação no /callback. Retorna dict com métricas do ciclo."""
    # Pega posts da página
    posts_data = fb_get(f"{client['page_id']}/posts",
                       {"fields": "id,message,created_time,permalink_url", "limit": max_posts},
                       access_token)
    posts = posts_data.get("data", [])

    # Upsert dos posts (para agrupar comentários no dashboard)
    save_posts(client["id"], posts)

    new_comments = []
    sample_comments = []
    posts_checked = len(posts)
    comments_found = 0
    comments_new_count = 0
    comments_analyzed = 0
    sentiments = []

    for post in posts:
        post_id = post["id"]
        comments_data, _ = fb_get_paginated(
            f"{post_id}/comments",
            {"fields": "id,from,message,created_time,like_count", "limit": 100, "order": "reverse_chronological"},
            access_token,
            max_items=max_comments
        )

        for c in comments_data:
            comments_found += 1
            comment_id = c["id"]
            author_name = c.get("from", {}).get("name", "Facebook User")
            message = c.get("message", "")
            created_time = c.get("created_time", datetime.now().isoformat())
            like_count = c.get("like_count", 0)

            if len(sample_comments) < 3:
                sample_comments.append(message[:50])

            # Tenta salvar (ON CONFLICT DO NOTHING retorna None se já existe)
            saved_id = save_comment(
                client["id"], comment_id, post_id, author_name,
                message, "NEUTRO", like_count, created_time, source
            )

            if saved_id:
                comments_new_count += 1
                new_comments.append({
                    "id": comment_id, "message": message,
                    "author": author_name, "post_id": post_id
                })

    # Analisa sentimento apenas dos novos comentários
    if new_comments:
        sentiments = analyze_and_update_comments(client["id"], new_comments)
        comments_analyzed = len(new_comments)

    # Calcula custo
    cost_brl = comments_analyzed * COST_PER_COMMENT_BRL

    # Atualiza estatísticas
    update_client_stats(client["id"], comments_new_count, cost_brl)

    # Salva log
    save_poll_log(client["id"], posts_checked, comments_found,
                 comments_new_count, comments_analyzed, cost_brl,
                 triggered_by=triggered_by)

    # Envia para webhook N8N do cliente
    if client.get("n8n_webhook_url") and new_comments:
        try:
            requests.post(client["n8n_webhook_url"], json={
                "client_id": client["id"],
                "page_name": client["page_name"],
                "new_comments": new_comments,
                "sentiments": sentiments,
                "timestamp": datetime.now().isoformat()
            }, timeout=10)
        except Exception as e:
            print(f"Erro ao enviar para N8N: {e}")

    return {
        "status": "ok",
        "client_id": client["id"],
        "page_name": client["page_name"],
        "posts_checked": posts_checked,
        "comments_found": comments_found,
        "comments_new": comments_new_count,
        "comments_analyzed": comments_analyzed,
        "cost_brl": cost_brl,
        "triggered_by": triggered_by,
        "debug": {
            "new_comments_count": comments_new_count,
            "sample_comments": sample_comments
        },
        "timestamp": datetime.now().isoformat()
    }


@app.route("/poll/<int:client_id>", methods=["GET", "POST"])
def poll_client(client_id):
    """N8N chama este endpoint para fazer polling de um cliente específico."""
    # Busca cliente
    conn = get_db_connection()
    try:
        set_rls_client(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, page_id, page_name, access_token_encrypted, n8n_webhook_url
                FROM clients WHERE id = %s AND is_active = TRUE
            """, (client_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Cliente não encontrado ou inativo"}), 404

            client = {
                "id": row[0], "page_id": row[1], "page_name": row[2],
                "access_token_encrypted": row[3], "n8n_webhook_url": row[4]
            }
    finally:
        conn.close()

    access_token = decrypt_token(client["access_token_encrypted"])
    if not access_token:
        return jsonify({"error": "Não foi possível descriptografar o token"}), 500

    try:
        return jsonify(run_poll_for_client(client, access_token, triggered_by="n8n"))
    except Exception as e:
        save_poll_log(client["id"], 0, 0, 0, 0, 0.0, str(e), "n8n")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# WEBHOOK (Meta envia eventos em tempo real)
# =============================================================================

@app.route("/webhook", methods=["GET"])
def webhook_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == WEBHOOK_VERIFY_TOKEN:
        print(f"Webhook verificado. Challenge: {challenge}")
        return challenge, 200
    return "Verificação falhou", 403


@app.route("/webhook", methods=["POST"])
def webhook_receive():
    signature = request.headers.get("X-Hub-Signature-256", "")
    payload_body = request.get_data()
    if not verify_signature(payload_body, signature):
        return "Assinatura inválida", 403

    try:
        payload = request.get_json()
        _WEBHOOK_EVENTS.append({
            "received_at": datetime.now().isoformat(),
            "payload": payload
        })

        # Extrai info do comentário
        info = extract_webhook_comment_info(payload)
        if info and info["item"] == "comment" and info["verb"] == "add":
            # Busca cliente pelo page_id
            client = get_client_by_page_id(info["page_id"])
            if client:
                # Analisa sentimento
                sentiment = analyze_sentiment(info["message"])

                # Salva comentário
                save_comment(
                    client["id"], 
                    info["comment_id"], 
                    info["post_id"],
                    info["author_name"], 
                    info["message"], 
                    sentiment,
                    0,  # like_count não vem no webhook
                    info["created_time"],
                    "webhook"
                )

                # Atualiza stats
                update_client_stats(client["id"], 1, COST_PER_COMMENT_BRL)

                # Envia para N8N
                if client["n8n_webhook_url"]:
                    try:
                        requests.post(client["n8n_webhook_url"], json={
                            "client_id": client["id"],
                            "page_name": client["page_name"],
                            "event": "new_comment",
                            "comment": info,
                            "sentiment": sentiment,
                            "timestamp": datetime.now().isoformat()
                        }, timeout=10)
                    except Exception as e:
                        print(f"Erro ao enviar webhook para N8N: {e}")

        return "EVENT_RECEIVED", 200
    except Exception as e:
        print(f"Erro processando webhook: {e}")
        return "Erro", 500


# =============================================================================
# HEALTH & UTILS
# =============================================================================

@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route("/webhook/logs")
def webhook_logs():
    logs = []
    for event in reversed(_WEBHOOK_EVENTS):
        info = extract_webhook_comment_info(event)
        if info:
            info["received_at"] = event["received_at"]
            logs.append(info)
    return jsonify(logs)

# =============================================================================
# ENDPOINT: Re-analisar sentimentos de comentarios existentes
# =============================================================================

@app.route("/reanalyze/<int:client_id>", methods=["POST", "GET"])
def reanalyze_comments(client_id):
    """Re-analisa sentimentos de comentarios ja existentes no banco."""
    try:
        conn = get_db_connection()
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            # Busca comentarios do cliente
            cur.execute("""
                SELECT comment_id, message 
                FROM comments 
                WHERE client_id = %s 
                ORDER BY created_time DESC
                LIMIT 100
            """, (client_id,))
            rows = cur.fetchall()
        
        if not rows:
            return jsonify({"status": "ok", "message": "Nenhum comentario encontrado", "reanalyzed": 0})
        
        # Prepara para analise em batch
        texts = [r[1] for r in rows if r[1]]
        comment_ids = [r[0] for r in rows if r[1]]
        
        print(f"[REANALYZE] Cliente {client_id}: {len(texts)} comentarios para re-analisar")
        
        # Analisa sentimentos
        sentiments = analyze_many(texts)
        
        # Atualiza no banco
        updated = 0
        with conn.cursor() as cur:
            for cid, sentiment in zip(comment_ids, sentiments):
                cur.execute("""
                    UPDATE comments 
                    SET sentiment = %s, analyzed_at = NOW() 
                    WHERE comment_id = %s AND client_id = %s
                """, (sentiment, cid, client_id))
                updated += 1
            conn.commit()
        
        conn.close()
        
        # Conta distribuicao
        counts = {"POSITIVO": 0, "NEUTRO": 0, "NEGATIVO": 0}
        for s in sentiments:
            if s in counts:
                counts[s] += 1
        
        return jsonify({
            "status": "ok",
            "client_id": client_id,
            "reanalyzed": updated,
            "sentiment_distribution": counts,
            "sample": list(zip(comment_ids[:5], sentiments[:5]))
        })
        
    except Exception as e:
        print(f"[REANALYZE] Erro: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
# =============================================================================
# MAIN (Vercel não usa isso, mas útil para teste local)
# =============================================================================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
