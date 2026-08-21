# Betelgeuse TI - Multitenant

Arquitetura multitenant para monitoramento de comentários do Facebook.

## Estrutura

```
betelgeuse-mt/
├── api/
│   └── app.py              # Flask API (Vercel)
├── admin/
│   └── superadmin.py       # Streamlit Backoffice
├── requirements.txt
├── vercel.json
└── .env.example
```

## Deploy no Vercel

1. Crie o projeto no Vercel: https://vercel.com/new
2. Importe o repositório Git
3. Configure as Environment Variables (ver `.env.example`)
4. Deploy!

## Banco de Dados

Execute o schema SQL no Supabase SQL Editor (já testado e validado).

### Migração 2026-08-19 (obrigatória antes do deploy desta versão)

Execute `supabase/migration_2026-08-19.sql` no Supabase SQL Editor. Ela cria:

- Tabela `posts` (comentários agrupados por post no dashboard)
- Colunas `first_import_at` e `first_import_count` em `clients`

### Freemium (Etapa 1)

Execute no Supabase SQL Editor:

```sql
ALTER TABLE clients ADD COLUMN IF NOT EXISTS paid_analysis_count INTEGER DEFAULT 0;
```

### Backfill de posts (histórico completo de uma página)

Para importar posts/comentários históricos de um cliente **sem custo**
(sentiment = NULL, sem Gemini, sem consumir cota):

```bash
SUPABASE_DB_URL=... TOKEN_SECRET=... python scripts/backfill_repow.py [--client-id N]
```

## Backoffice Streamlit

```bash
pip install -r requirements.txt
streamlit run admin/superadmin.py
```

## Fluxo do Cliente

1. Acessa `betelgeuse-mt.vercel.app`
2. Clica "Conectar com Facebook"
3. Autoriza o app na própria página
4. **Primeira importação**: a API baixa e analisa os comentários históricos
   (limite: 10 posts × 200 comentários, por restrição de timeout serverless),
   cobrando R$ 0,20 por comentário analisado
5. Recebe API Key
6. Acessa dashboard com `/client/{api_key}/dashboard`
   (comentários agrupados por post, com link para o Facebook)
7. Consulta faturamento transparente em `/client/{api_key}/billing`
   (detalhamento mensal + histórico de sincronizações, imprimível em PDF)

## Fluxo do N8N

1. N8N chama `POST /poll/{client_id}` a cada 1h
2. API busca posts e comentários novos no Facebook (upsert em `posts`)
3. Analisa sentimento via Gemini **apenas dos comentários novos, até o limite da cota**
   (freemium: `FREE_ANALYSIS_LIMIT` = 50 análises grátis + `paid_analysis_count` pagas;
   o excedente é salvo com `sentiment = NULL`, sem custo, recuperável depois)
4. Salva no Supabase
5. Envia webhook para URL do cliente (payload inclui `quota_exceeded` e `comments_skipped_quota`)

> O webhook em tempo real (`/webhook`) segue a mesma cota: sem saldo, o
> comentário é salvo sem análise e o payload vai com `quota_exceeded: true`.

> Os resumos de manhã / meio-dia / fim de tarde são fluxos do N8N que
> consomem `GET /client/{api_key}/comments` — nada a configurar na API.

## Webhooks em Tempo Real

1. Meta envia POST para `/webhook`
2. API valida assinatura HMAC
3. Extrai comentário, analisa sentimento
4. Salva no Supabase + envia para N8N do cliente
