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

## Backoffice Streamlit

```bash
pip install -r requirements.txt
streamlit run admin/superadmin.py
```

## Fluxo do Cliente

1. Acessa `betelgeuse-mt.vercel.app`
2. Clica "Conectar com Facebook"
3. Autoriza o app na própria página
4. Recebe API Key
5. Acessa dashboard com `/client/{api_key}/dashboard`

## Fluxo do N8N

1. N8N chama `POST /poll/{client_id}` a cada 1h
2. API busca comentários novos no Facebook
3. Analisa sentimento via Gemini
4. Salva no Supabase
5. Envia webhook para URL do cliente

## Webhooks em Tempo Real

1. Meta envia POST para `/webhook`
2. API valida assinatura HMAC
3. Extrai comentário, analisa sentimento
4. Salva no Supabase + envia para N8N do cliente
