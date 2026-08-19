-- ============================================================
-- Betelgeuse MT - Migração 2026-08-19 (backfill + relatório diário)
-- 1) Colunas de checkpoint do backfill em `clients`
-- 2) View `daily_usage` (relatório diário sem tabela nova)
-- A tabela `posts` (e seu RLS) já foi criada em migration_2026-08-19.sql.
-- Execute no Supabase SQL Editor ANTES do deploy da nova versão.
-- ============================================================

-- Checkpoint do backfill (captura completa do histórico da página)
-- backfill_status: 'pending' | 'running' | 'done'
ALTER TABLE clients ADD COLUMN IF NOT EXISTS backfill_status TEXT DEFAULT 'pending';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS backfill_cursor TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS backfill_completed_at TIMESTAMPTZ;

-- View de uso diário por cliente.
-- O custo é calculado na aplicação (comments_analyzed × COST_PER_COMMENT_BRL),
-- assim o preço não fica hardcoded no banco.
CREATE OR REPLACE VIEW daily_usage AS
SELECT client_id,
       DATE(analyzed_at) AS day,
       COUNT(*) AS comments_analyzed
FROM comments
WHERE analyzed_at IS NOT NULL
GROUP BY client_id, DATE(analyzed_at);
