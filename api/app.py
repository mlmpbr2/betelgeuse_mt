"""
Betelgeuse TI - Multitenant API
Flask app para Vercel - Cada cliente conecta sua própria página do Facebook
Versão: 2026-08-17
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
                       api_key, n8n_webhook_url, is_active, total_comments_processed, total_cost_brl
                FROM clients WHERE api_key = %s AND is_active = TRUE
            """, (api_key,))
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


def save_client(name, email, page_id, page_name, access_token, n8n_webhook_url=""):
    """Salva novo cliente no Supabase."""
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
                    api_key = EXCLUDED.api_key,
                    n8n_webhook_url = EXCLUDED.n8n_webhook_url,
                    is_active = TRUE
                RETURNING id, api_key
            """, (name, email, page_id, page_name, encrypted_token, api_key, n8n_webhook_url))
            row = cur.fetchone()
            conn.commit()
            return {"id": row[0], "api_key": row[1]}
    finally:
        conn.close()


def save_comment(client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source="webhook"):
    """Salva comentário no Supabase."""
    conn = get_db_connection()
    try:
        set_rls_client(conn, client_id=client_id)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO comments (client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (client_id, comment_id) DO NOTHING
                RETURNING id
            """, (client_id, comment_id, post_id, author_name, message, sentiment, like_count, created_time, source))
            row = cur.fetchone()
            conn.commit()
            return row[0] if row else None
    except Exception as e:
        print(f"Error saving comment: {e}")
        return None
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
                "maxOutputTokens": 50,
                "responseMimeType": "application/json"
            }
        }
        resp = requests.post(url, json=payload, timeout=30)
        data = resp.json()
        print(f"[SENTIMENT] API status={resp.status_code}, response={json.dumps(data)[:300]}")

        if "candidates" in data and data["candidates"]:
            result = data["candidates"][0]["content"]["parts"][0]["text"].upper().strip()
            print(f"[SENTIMENT] Raw result: '{result}'")
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
                "maxOutputTokens": 500,
                "responseMimeType": "application/json"
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

        result_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        print(f"[SENTIMENT-BATCH] Raw result: {result_text[:300]}")

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
        .comment-card.positive { border-left-color: #2e7d32; background: #e8f5e9; }
        .comment-card.neutral { border-left-color: #f9a825; background: #fff8e1; }
        .comment-card.negative { border-left-color: #c62828; background: #ffebee; }
        .sentiment-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .sentiment-positive { background: #2e7d32; color: white; }
        .sentiment-neutral { background: #f9a825; color: white; }
        .sentiment-negative { background: #c62828; color: white; }
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
        </div>
        <div style="text-align: right;">
            <p style="font-size: 12px; color: #65676b;">Comentários processados</p>
            <p style="font-size: 24px; font-weight: 700; color: #1877f2;">{{ client.total_comments_processed }}</p>
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

<div class="card">
    <div class="card-title">💬 Últimos Comentários</div>
    {% for comment in comments %}
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
            ❤️ {{ comment.like_count }} likes | 
            📝 Post: {{ comment.post_id }}
        </div>
    </div>
    {% else %}
    <p style="color: #65676b; text-align: center; padding: 20px;">Nenhum comentário encontrado ainda.</p>
    {% endfor %}
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

        # Pega a primeira página (ou poderia ter um seletor)
        page = pages[0]
        page_id = page["id"]
        page_name = page["name"]
        page_token = page.get("access_token", user_token)

        # Salva no Supabase
        result = save_client(user_name, user_email, page_id, page_name, page_token)

        # Renderiza sucesso
        content = render_template_string(SUCCESS_TEMPLATE, 
            page_name=page_name, 
            page_id=page_id, 
            api_key=result["api_key"]
        )
        return render_template_string(BASE_TEMPLATE, content=content)

    except Exception as e:
        return f"Erro: {str(e)}", 500


@app.route("/client/<api_key>/dashboard")
def client_dashboard(api_key):
    client = get_client_by_api_key(api_key)
    if not client:
        return "Cliente não encontrado", 404

    comments = get_client_comments(client["id"], limit=50)
    sentiment_counts = {"POSITIVO": 0, "NEUTRO": 0, "NEGATIVO": 0}
    for c in comments:
        if c["sentiment"] in sentiment_counts:
            sentiment_counts[c["sentiment"]] += 1

    content = render_template_string(CLIENT_DASHBOARD_TEMPLATE, 
        client=client, 
        comments=comments,
        sentiment_counts=sentiment_counts
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
        "client": {"name": client["name"], "page_name": client["page_name"]},
        "comments": comments,
        "total": len(comments)
    })


# =============================================================================
# POLLING (N8N chama este endpoint)
# =============================================================================

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
        # Pega posts da página
        posts_data = fb_get(f"{client['page_id']}/posts", 
                           {"fields": "id,message,created_time", "limit": 10}, 
                           access_token)
        posts = posts_data.get("data", [])

        all_comments = []
        new_comments = []
        posts_checked = len(posts)
        comments_found = 0
        comments_new_count = 0
        comments_analyzed = 0

        for post in posts:
            post_id = post["id"]
            comments_data, _ = fb_get_paginated(
                f"{post_id}/comments",
                {"fields": "id,from,message,created_time,like_count", "limit": 100, "order": "reverse_chronological"},
                access_token,
                max_items=200
            )

            for c in comments_data:
                comments_found += 1
                comment_id = c["id"]
                author_name = c.get("from", {}).get("name", "Facebook User")
                message = c.get("message", "")
                created_time = c.get("created_time", datetime.now().isoformat())
                like_count = c.get("like_count", 0)

                # Tenta salvar (ON CONFLICT DO NOTHING retorna None se já existe)
                saved_id = save_comment(
                    client["id"], comment_id, post_id, author_name, 
                    message, "NEUTRO", like_count, created_time, "polling"
                )

                if saved_id:
                    comments_new_count += 1
                    new_comments.append({
                        "id": comment_id, "message": message, 
                        "author": author_name, "post_id": post_id
                    })

                all_comments.append({"message": message, "is_new": saved_id is not None, "saved_id": saved_id})

        # Analisa sentimento apenas dos novos comentários
        if new_comments:
            texts = [c["message"] for c in new_comments]
            sentiments = analyze_many(texts)

            # Atualiza sentimentos no banco
            conn = get_db_connection()
            try:
                set_rls_client(conn, client_id=client["id"])
                with conn.cursor() as cur:
                    for nc, sentiment in zip(new_comments, sentiments):
                        cur.execute("""
                            UPDATE comments SET sentiment = %s, analyzed_at = NOW()
                            WHERE client_id = %s AND comment_id = %s
                        """, (sentiment, client["id"], nc["id"]))
                    conn.commit()
            finally:
                conn.close()

            comments_analyzed = len(new_comments)

        # Calcula custo
        cost_brl = comments_analyzed * COST_PER_COMMENT_BRL

        # Atualiza estatísticas
        update_client_stats(client["id"], comments_new_count, cost_brl)

        # Salva log
        save_poll_log(client["id"], posts_checked, comments_found, 
                     comments_new_count, comments_analyzed, cost_brl, 
                     triggered_by="n8n")

        # Envia para webhook N8N do cliente
        if client["n8n_webhook_url"] and new_comments:
            try:
                requests.post(client["n8n_webhook_url"], json={
                    "client_id": client["id"],
                    "page_name": client["page_name"],
                    "new_comments": new_comments,
                    "sentiments": sentiments if new_comments else [],
                    "timestamp": datetime.now().isoformat()
                }, timeout=10)
            except Exception as e:
                print(f"Erro ao enviar para N8N: {e}")

        return jsonify({
            "status": "ok",
            "client_id": client["id"],
            "page_name": client["page_name"],
            "posts_checked": posts_checked,
            "comments_found": comments_found,
            "comments_new": comments_new_count,
            "comments_analyzed": comments_analyzed,
            "cost_brl": cost_brl,
            "debug": {
                "total_in_db_before": len(all_comments),
                "new_comments_count": comments_new_count,
                "sample_comments": [c["message"][:50] for c in all_comments[:3]]
            },
            "timestamp": datetime.now().isoformat()
        })

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
