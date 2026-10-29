#!/usr/bin/env bash
# Gera valores novos para os segredos da API. Imprime no terminal e NÃO grava em arquivo:
# copie para o painel da Vercel / Railway (variáveis de ambiente) e para o seu gerenciador de senhas.
set -euo pipefail
for name in INTERNAL_SECRET TOKEN_ENCRYPTION_KEY AI_SERVICE_TOKEN CRON_SECRET; do
  printf '%s=%s\n' "$name" "$(openssl rand -hex 32)"
done
echo
echo "Troque também (gerados nos painéis dos provedores, não aqui):"
echo "  - UPSTASH_REDIS_REST_TOKEN  (console da Upstash: Reset Password / Rotate Token)"
echo "  - chaves de API rkwy_live_  (revogue as antigas e emita novas)"
