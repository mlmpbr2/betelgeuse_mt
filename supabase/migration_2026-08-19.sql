-- ============================================================
-- Betelgeuse MT - Migração 2026-08-19
-- 1) Tabela `posts` (comentários agrupados por post no dashboard)
-- 2) Colunas de primeira importação em `clients`
-- Execute no Supabase SQL Editor ANTES do deploy da nova versão.
-- ============================================================

-- Tabela de posts (1 registro por post do Facebook por cliente)
CREATE TABLE IF NOT EXISTS posts (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    post_id TEXT NOT NULL,
    message TEXT,
    permalink_url TEXT,
    created_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (client_id, post_id)
);

CREATE INDEX IF NOT EXISTS idx_posts_client_id ON posts(client_id);

-- RLS no mesmo padrão das tabelas existentes
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY posts_client_select ON posts FOR SELECT
    USING (client_id::text = current_setting('app.current_client_id', true)
           OR current_setting('app.is_superadmin', true) = 'true');

CREATE POLICY posts_client_insert ON posts FOR INSERT
    WITH CHECK (client_id::text = current_setting('app.current_client_id', true)
           OR current_setting('app.is_superadmin', true) = 'true');

CREATE POLICY posts_client_update ON posts FOR UPDATE
    USING (client_id::text = current_setting('app.current_client_id', true)
           OR current_setting('app.is_superadmin', true) = 'true');

-- Colunas de primeira importação no cliente
ALTER TABLE clients ADD COLUMN IF NOT EXISTS first_import_at TIMESTAMPTZ;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS first_import_count INT DEFAULT 0;
