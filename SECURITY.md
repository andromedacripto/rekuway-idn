# Política de segurança

## Reportar uma vulnerabilidade

**Não abra uma issue pública.** Use *Security → Report a vulnerability* na aba do repositório no GitHub. Descreva o impacto e os passos para reproduzir. Não teste contra dados de terceiros.

## Segredos

- Nenhum segredo é versionado. Os modelos são `.env.example` e `ai-service/.env.example.txt`.
- O hook de pre-commit e o CI rodam `scripts/secret-scan.mjs` (arquivos novos, árvore inteira e **todo o histórico**). Um segredo detectado bloqueia o commit e o merge.
- Ative também, nas configurações do repositório, *Secret scanning* e *Push protection*.
- Para gerar valores novos: `./scripts/generate-secrets.sh`.

## Se um segredo vazar

1. **Troque a credencial primeiro** (reescrever o histórico não desfaz um vazamento).
2. Remova o arquivo e reescreva o histórico (`git filter-repo`), depois force o push e peça ao suporte do GitHub para limpar caches e refs de pull requests.
3. Confira com `npm run secrets:scan:history`.
