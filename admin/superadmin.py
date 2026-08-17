"""
Betelgeuse TI - Superadmin Backoffice
Streamlit app para gestão multitenant
Versão: 2026-08-17
"""

import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

# =============================================================================
# CONFIG
# =============================================================================
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "")

st.set_page_config(
    page_title="Betelgeuse TI - Superadmin",
    page_icon="🌟",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db_connection():
    if not SUPABASE_DB_URL:
        st.error("❌ SUPABASE_DB_URL não configurada nas variáveis de ambiente!")
        st.stop()
    return psycopg2.connect(SUPABASE_DB_URL)


def set_rls_superadmin(conn):
    with conn.cursor() as cur:
        cur.execute("SET LOCAL app.is_superadmin = 'true';")
        cur.execute("SET LOCAL app.current_client_id = '0';")
        conn.commit()


def verify_superadmin(email, password):
    """Verifica login do superadmin."""
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, email, name, password_hash, is_active
                FROM superadmin_users WHERE email = %s AND is_active = TRUE
            """, (email,))
            user = cur.fetchone()
            if not user:
                return None
            # Verifica SHA256 da senha
            import hashlib
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            if pwd_hash == user["password_hash"]:
                # Atualiza last_login
                cur.execute("""
                    UPDATE superadmin_users SET last_login_at = NOW() WHERE id = %s
                """, (user["id"],))
                conn.commit()
                return dict(user)
            return None
    finally:
        conn.close()


def get_superadmin_stats():
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM get_superadmin_stats()")
            return dict(cur.fetchone())
    finally:
        conn.close()


def get_all_clients():
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, name, email, page_id, page_name, api_key, 
                       is_active, created_at, last_poll_at,
                       total_comments_processed, total_cost_brl
                FROM clients ORDER BY created_at DESC
            """)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_client_comments(client_id, limit=100):
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT comment_id, post_id, author_name, message, sentiment,
                       like_count, created_time, analyzed_at, source
                FROM comments WHERE client_id = %s
                ORDER BY created_time DESC LIMIT %s
            """, (client_id, limit))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_sentiment_breakdown(client_id):
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM get_sentiment_breakdown(%s)", (client_id,))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_billing_summary():
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT bs.*, c.name as client_name, c.page_name
                FROM billing_summary bs
                JOIN clients c ON c.id = bs.client_id
                ORDER BY bs.year_month DESC, bs.cost_brl DESC
            """)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_poll_logs(client_id=None, limit=50):
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if client_id:
                cur.execute("""
                    SELECT pl.*, c.name as client_name
                    FROM poll_logs pl
                    JOIN clients c ON c.id = pl.client_id
                    WHERE pl.client_id = %s
                    ORDER BY pl.polled_at DESC LIMIT %s
                """, (client_id, limit))
            else:
                cur.execute("""
                    SELECT pl.*, c.name as client_name
                    FROM poll_logs pl
                    JOIN clients c ON c.id = pl.client_id
                    ORDER BY pl.polled_at DESC LIMIT %s
                """, (limit,))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_webhook_events(limit=50):
    conn = get_db_connection()
    try:
        set_rls_superadmin(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT we.*, c.name as client_name
                FROM webhook_events we
                LEFT JOIN clients c ON c.id = we.client_id
                ORDER BY we.received_at DESC LIMIT %s
            """, (limit,))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


# =============================================================================
# AUTH
# =============================================================================

def login_page():
    st.title("🌟 Betelgeuse TI - Superadmin")
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.subheader("🔐 Login do Administrador")
        email = st.text_input("Email", value="admin@betelgeuse.com")
        password = st.text_input("Senha", type="password")

        if st.button("Entrar", type="primary", use_container_width=True):
            user = verify_superadmin(email, password)
            if user:
                st.session_state["superadmin"] = user
                st.success(f"✅ Bem-vindo, {user['name']}!")
                st.rerun()
            else:
                st.error("❌ Email ou senha incorretos")

        st.info("💡 Senha padrão: **admin123** (troque após o primeiro acesso)")


def logout():
    if "superadmin" in st.session_state:
        del st.session_state["superadmin"]
    st.rerun()


# =============================================================================
# PAGES
# =============================================================================

def dashboard_page():
    st.title("📊 Dashboard Global")

    stats = get_superadmin_stats()

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("👥 Clientes Ativos", stats.get("total_clients", 0))
    with col2:
        st.metric("💬 Total Comentários", stats.get("total_comments", 0))
    with col3:
        st.metric("💰 Receita Total", f"R$ {stats.get('total_revenue', 0):,.2f}")
    with col4:
        st.metric("📅 Comentários Hoje", stats.get("comments_today", 0))
    with col5:
        st.metric("💵 Receita Hoje", f"R$ {stats.get('revenue_today', 0):,.2f}")

    st.markdown("---")

    # Gráfico de clientes
    clients = get_all_clients()
    if clients:
        df_clients = pd.DataFrame(clients)
        df_clients["created_at"] = pd.to_datetime(df_clients["created_at"])

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("💰 Faturamento por Cliente")
            fig = px.bar(
                df_clients.sort_values("total_cost_brl", ascending=True).tail(10),
                x="total_cost_brl", y="name", orientation="h",
                color="total_cost_brl", color_continuous_scale="Blues",
                labels={"total_cost_brl": "R$", "name": "Cliente"}
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("💬 Comentários Processados por Cliente")
            fig = px.bar(
                df_clients.sort_values("total_comments_processed", ascending=True).tail(10),
                x="total_comments_processed", y="name", orientation="h",
                color="total_comments_processed", color_continuous_scale="Greens",
                labels={"total_comments_processed": "Comentários", "name": "Cliente"}
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("👥 Todos os Clientes")
        df_display = df_clients[["id", "name", "email", "page_name", "is_active", 
                                  "total_comments_processed", "total_cost_brl", "created_at"]]
        df_display.columns = ["ID", "Nome", "Email", "Página", "Ativo", 
                              "Comentários", "Custo (R$)", "Criado em"]
        st.dataframe(df_display, use_container_width=True, hide_index=True)


def client_detail_page(client_id):
    clients = get_all_clients()
    client = next((c for c in clients if c["id"] == client_id), None)
    if not client:
        st.error("Cliente não encontrado")
        return

    st.title(f"👤 {client['name']}")
    st.caption(f"Página: {client['page_name']} | ID: {client['page_id']}")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Comentários", client["total_comments_processed"])
    with col2:
        st.metric("Custo Total", f"R$ {client['total_cost_brl']:,.2f}")
    with col3:
        st.metric("Status", "✅ Ativo" if client["is_active"] else "❌ Inativo")
    with col4:
        last_poll = client["last_poll_at"].strftime("%d/%m %H:%M") if client["last_poll_at"] else "Nunca"
        st.metric("Último Poll", last_poll)

    st.markdown("---")

    # Sentiment breakdown
    sentiments = get_sentiment_breakdown(client_id)
    if sentiments:
        df_sent = pd.DataFrame(sentiments)
        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(df_sent, values="count", names="sentiment", 
                        color="sentiment", color_discrete_map={
                            "POSITIVO": "#2e7d32", "NEUTRO": "#f9a825", "NEGATIVO": "#c62828"
                        })
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("📊 Distribuição")
            for s in sentiments:
                emoji = "😊" if s["sentiment"] == "POSITIVO" else "😐" if s["sentiment"] == "NEUTRO" else "😠"
                st.write(f"{emoji} **{s['sentiment']}**: {s['count']} ({s['percentage']}%)")

    # Comentários
    st.subheader("💬 Últimos Comentários")
    comments = get_client_comments(client_id, limit=50)
    if comments:
        df_comments = pd.DataFrame(comments)
        df_comments["created_time"] = pd.to_datetime(df_comments["created_time"])

        # Filtro de sentimento
        sentiment_filter = st.selectbox("Filtrar por sentimento", ["Todos", "POSITIVO", "NEUTRO", "NEGATIVO"])
        if sentiment_filter != "Todos":
            df_comments = df_comments[df_comments["sentiment"] == sentiment_filter]

        for _, row in df_comments.head(20).iterrows():
            color = "🟢" if row["sentiment"] == "POSITIVO" else "🟡" if row["sentiment"] == "NEUTRO" else "🔴"
            with st.container(border=True):
                cols = st.columns([1, 8, 2])
                with cols[0]:
                    st.write(color)
                with cols[1]:
                    st.write(f"**{row['author_name']}**: {row['message'][:200]}")
                    st.caption(f"📅 {row['created_time'].strftime('%d/%m/%Y %H:%M')} | ❤️ {row['like_count']} | 📝 {row['post_id']}")
                with cols[2]:
                    st.badge(row["sentiment"])
    else:
        st.info("Nenhum comentário encontrado para este cliente.")


def billing_page():
    st.title("💰 Faturamento")

    billing = get_billing_summary()
    if billing:
        df = pd.DataFrame(billing)
        df["year_month"] = pd.to_datetime(df["year_month"] + "-01")

        col1, col2 = st.columns(2)
        with col1:
            total_revenue = df["cost_brl"].sum()
            st.metric("💰 Receita Total", f"R$ {total_revenue:,.2f}")
        with col2:
            total_comments = df["comments_new"].sum()
            st.metric("💬 Comentários Faturados", f"{total_comments:,}")

        st.subheader("📈 Evolução Mensal")
        monthly = df.groupby("year_month").agg({
            "cost_brl": "sum", "comments_new": "sum"
        }).reset_index()
        fig = go.Figure()
        fig.add_trace(go.Bar(x=monthly["year_month"], y=monthly["cost_brl"], name="Receita (R$)", marker_color="#1877f2"))
        fig.add_trace(go.Scatter(x=monthly["year_month"], y=monthly["comments_new"], name="Comentários", yaxis="y2", line=dict(color="#2e7d32")))
        fig.update_layout(yaxis2=dict(overlaying="y", side="right"), legend=dict(orientation="h"))
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("📋 Detalhamento por Cliente/Mês")
        df_display = df[["client_name", "page_name", "year_month", "comments_new", "comments_total", "cost_brl", "paid"]]
        df_display.columns = ["Cliente", "Página", "Mês", "Novos", "Total", "Custo (R$)", "Pago"]
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum dado de faturamento ainda.")


def logs_page():
    st.title("📋 Logs de Polling")

    clients = get_all_clients()
    client_options = {"Todos": None}
    client_options.update({c["name"]: c["id"] for c in clients})
    selected = st.selectbox("Filtrar por cliente", list(client_options.keys()))

    logs = get_poll_logs(client_id=client_options[selected], limit=100)
    if logs:
        df = pd.DataFrame(logs)
        df["polled_at"] = pd.to_datetime(df["polled_at"])

        st.subheader("📊 Estatísticas dos Logs")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total de Polls", len(df))
        with col2:
            st.metric("Comentários Novos", df["comments_new"].sum())
        with col3:
            st.metric("Comentários Analisados", df["comments_analyzed"].sum())
        with col4:
            st.metric("Custo Total", f"R$ {df['cost_brl'].sum():,.2f}")

        st.subheader("📋 Logs Recentes")
        df_display = df[["client_name", "polled_at", "posts_checked", "comments_found", 
                         "comments_new", "comments_analyzed", "cost_brl", "triggered_by"]]
        df_display.columns = ["Cliente", "Data", "Posts", "Encontrados", "Novos", "Analisados", "Custo (R$)", "Origem"]
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum log de polling encontrado.")


def webhook_events_page():
    st.title("📡 Eventos de Webhook")

    events = get_webhook_events(limit=100)
    if events:
        df = pd.DataFrame(events)
        df["received_at"] = pd.to_datetime(df["received_at"])

        st.metric("Total de Eventos", len(df))

        st.subheader("📋 Eventos Recentes")
        df_display = df[["client_name", "received_at", "page_id", "comment_id", "event_type", "processed"]]
        df_display.columns = ["Cliente", "Recebido em", "Page ID", "Comment ID", "Tipo", "Processado"]
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum evento de webhook recebido ainda.")


# =============================================================================
# MAIN
# =============================================================================

def main():
    # CSS customizado
    st.markdown("""
    <style>
    .stMetric { background: white; padding: 10px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    </style>
    """, unsafe_allow_html=True)

    if "superadmin" not in st.session_state:
        login_page()
        return

    user = st.session_state["superadmin"]

    with st.sidebar:
        st.title("🌟 Betelgeuse TI")
        st.write(f"👤 **{user['name']}**")
        st.caption(f"{user['email']}")
        st.markdown("---")

        page = st.radio("Navegação", [
            "📊 Dashboard",
            "👥 Clientes",
            "💰 Faturamento",
            "📋 Logs de Polling",
            "📡 Webhook Events"
        ])

        st.markdown("---")
        if st.button("🚪 Sair", use_container_width=True):
            logout()

    if page == "📊 Dashboard":
        dashboard_page()
    elif page == "👥 Clientes":
        clients = get_all_clients()
        if not clients:
            st.info("Nenhum cliente cadastrado ainda.")
        else:
            st.title("👥 Clientes")
            for c in clients:
                col1, col2, col3 = st.columns([3, 2, 1])
                with col1:
                    st.write(f"**{c['name']}**")
                    st.caption(f"{c['page_name']} | {c['email']}")
                with col2:
                    st.write(f"💬 {c['total_comments_processed']} comentários")
                    st.write(f"💰 R$ {c['total_cost_brl']:,.2f}")
                with col3:
                    if st.button("Ver detalhes", key=f"btn_{c['id']}"):
                        st.session_state["selected_client"] = c["id"]
                        st.rerun()
                st.divider()

            if "selected_client" in st.session_state:
                client_detail_page(st.session_state["selected_client"])
    elif page == "💰 Faturamento":
        billing_page()
    elif page == "📋 Logs de Polling":
        logs_page()
    elif page == "📡 Webhook Events":
        webhook_events_page()


if __name__ == "__main__":
    main()
