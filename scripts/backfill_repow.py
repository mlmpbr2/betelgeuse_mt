"""
Betelgeuse MT - Backfill de posts da Repow (standalone, sem rota HTTP)

Busca TODOS os posts da página no Facebook e salva na tabela `posts`,
depois salva os comentários de cada post com sentiment = NULL
(sem Gemini, sem custo, sem consumir cota freemium).

Uso:
    python scripts/backfill_repow.py              # localiza a Repow por nome
    python scripts/backfill_repow.py --client-id 3
    python scripts/backfill_repow.py --yes        # pula a confirmação

Env vars necessárias: SUPABASE_DB_URL e TOKEN_SECRET (mesmas da API).
"""

import os
import sys
import base64
import argparse
import requests
import psycopg2
from cryptography.fernet import Fernet

FB_API_VERSION = "v25.0"
FB_BASE_URL = f"https://graph.facebook.com/{FB_API_VERSION}"

SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "")
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "")


def get_db_connection():
    if not SUPABASE_DB_URL:
        sys.exit("Erro: SUPABASE_DB_URL não configurada no ambiente.")
    return psycopg2.connect(SUPABASE_DB_URL)


def set_rls(conn, client_id=None, is_superadmin=False):
    """Mesmo padrão de set_rls_client() da API (api/app.py)."""
    with conn.cursor() as cur:
        cur.execute("SET LOCAL app.is_superadmin = %s;",
                    ('true' if is_superadmin else 'false',))
        cur.execute("SET LOCAL app.current_client_id = %s;",
                    (str(client_id) if client_id else '0',))
        conn.commit()


def decrypt_token(encrypted_token):
    """Replica a derivação Fernet da API (api/app.py)."""
    if not TOKEN_SECRET:
        sys.exit("Erro: TOKEN_SECRET não configurada no ambiente.")
    key_bytes = TOKEN_SECRET.encode()[:32].ljust(32, b'0')
    fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
    try:
        return fernet.decrypt(encrypted_token.encode()).decode()
    except Exception as e:
        sys.exit(f"Erro ao descriptografar o token do cliente: {e}")


def find_client(client_id=None):
    """Localiza o cliente Repow (ou o id informado) no Supabase."""
    conn = get_db_connection()
    try:
        set_rls(conn, is_superadmin=True)
        with conn.cursor() as cur:
            if client_id:
                cur.execute("""
                    SELECT id, name, page_id, page_name, access_token_encrypted
                    FROM clients WHERE id = %s AND is_active = TRUE
                """, (client_id,))
            else:
                cur.execute("""
                    SELECT id, name, page_id, page_name, access_token_encrypted
                    FROM clients
                    WHERE is_active = TRUE
                      AND (page_name ILIKE '%repow%' OR name ILIKE '%repow%')
                """)
            rows = cur.fetchall()
    finally:
        conn.close()

    if not rows:
        sys.exit("Erro: cliente Repow não encontrado (use --client-id).")
    if len(rows) > 1:
        print("Mais de um cliente encontrado:")
        for r in rows:
            print(f"  id={r[0]} | {r[1]} | página: {r[3]} (page_id={r[2]})")
        sys.exit("Refine com --client-id.")
    r = rows[0]
    return {"id": r[0], "name": r[1], "page_id": r[2],
            "page_name": r[3], "access_token_encrypted": r[4]}


def fb_paginated(url_path, params, access_token):
    """GET paginado na Graph API, sem limite artificial. Aborta em erro."""
    items = []
    url = f"{FB_BASE_URL}/{url_path}"
    next_params = {**params, "access_token": access_token}
    while True:
        resp = requests.get(url, params=next_params, timeout=30)
        data = resp.json()
        if "error" in data:
            err = data["error"]
            sys.exit(f"Erro na Graph API ({url_path}): "
                     f"{err.get('code')} {err.get('message')}")
        items.extend(data.get("data", []))
        next_url = data.get("paging", {}).get("next")
        if not next_url:
            return items
        url = next_url
        next_params = {}


def upsert_posts(client_id, posts):
    """Upsert em lote na tabela posts (mesmo SQL de save_posts() da API)."""
    if not posts:
        return
    conn = get_db_connection()
    try:
        set_rls(conn, client_id=client_id)
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
    finally:
        conn.close()


def insert_comments(client_id, post_id, comments):
    """Insere comentários com sentiment NULL (sem custo, sem cota).
    ON CONFLICT preserva comentários já analisados pela primeira importação."""
    if not comments:
        return 0, 0
    inserted = 0
    conn = get_db_connection()
    try:
        set_rls(conn, client_id=client_id)
        with conn.cursor() as cur:
            for c in comments:
                cur.execute("""
                    INSERT INTO comments (client_id, comment_id, post_id, author_name,
                                          message, sentiment, like_count, created_time,
                                          source, is_new)
                    VALUES (%s, %s, %s, %s, %s, NULL, %s, %s, 'backfill', FALSE)
                    ON CONFLICT (client_id, comment_id) DO NOTHING
                """, (client_id, c["id"], post_id,
                      c.get("from", {}).get("name", "Facebook User"),
                      c.get("message", ""), c.get("like_count", 0),
                      c.get("created_time")))
                inserted += cur.rowcount
            conn.commit()
    finally:
        conn.close()
    return inserted, len(comments) - inserted


def mark_backfill_done(client_id):
    conn = get_db_connection()
    try:
        set_rls(conn, is_superadmin=True)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE clients
                SET backfill_status = 'done', backfill_cursor = NULL,
                    backfill_completed_at = NOW()
                WHERE id = %s
            """, (client_id,))
            conn.commit()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Backfill de posts da Repow (sem custo Gemini)")
    parser.add_argument("--client-id", type=int, default=None,
                        help="ID do cliente no banco (pula a busca por nome)")
    parser.add_argument("--yes", action="store_true", help="Pula a confirmação")
    args = parser.parse_args()

    client = find_client(args.client_id)
    print(f"Cliente: {client['name']} (id={client['id']})")
    print(f"Página:  {client['page_name']} (page_id={client['page_id']})")

    token = decrypt_token(client["access_token_encrypted"])

    print("\nBuscando posts no Facebook...")
    posts = fb_paginated(f"{client['page_id']}/posts",
                         {"fields": "id,message,created_time,permalink_url",
                          "limit": 100}, token)
    print(f"Posts encontrados: {len(posts)}")

    if not args.yes:
        resp = input(f"\nSalvar {len(posts)} posts e seus comentários "
                     f"(sentiment=NULL, custo R$ 0,00)? [s/N] ")
        if resp.strip().lower() not in ("s", "sim", "y", "yes"):
            sys.exit("Abortado pelo usuário.")

    upsert_posts(client["id"], posts)
    print(f"Posts upsertados: {len(posts)}")

    total_new = 0
    total_existing = 0
    for i, post in enumerate(posts, 1):
        comments = fb_paginated(f"{post['id']}/comments",
                                {"fields": "id,from,message,created_time,like_count",
                                 "limit": 100, "order": "reverse_chronological"}, token)
        new, existing = insert_comments(client["id"], post["id"], comments)
        total_new += new
        total_existing += existing
        print(f"[{i}/{len(posts)}] post {post['id']}: "
              f"{len(comments)} comentários ({new} novos, {existing} já existiam)")

    mark_backfill_done(client["id"])

    print("\n=== Backfill concluído ===")
    print(f"Posts salvos:        {len(posts)}")
    print(f"Comentários novos:   {total_new} (sentiment=NULL)")
    print(f"Já existentes:       {total_existing} (preservados)")
    print(f"Custo:               R$ 0,00 (nenhuma análise Gemini)")


if __name__ == "__main__":
    main()
