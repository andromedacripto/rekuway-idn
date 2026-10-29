# Changelog

## 2.1.0

Rodada de correções de segurança e novas defesas. Detalhes e limites em `PENTEST.md` e `docs/INTEGRATION.md`.

### Segurança
- Segredos removidos do repositório e do histórico do git; scanner de segredos no pre-commit e no CI.
- `INTERNAL_SECRET` agora falha fechado (sem segredo configurado, tudo é recusado) e é comparado em tempo constante.
- Rotas `/api-keys` exigem `x-internal-secret`; a chave de API só vale no header `Authorization`.
- Chave privada guardada no Redis fica cifrada (AES-256-GCM).
- Rate limit por IP confiável (`X-Real-IP`), com fail-closed para rotas sensíveis quando o Redis falha.
- CORS por lista de origens (`ALLOWED_ORIGINS`) na API e no serviço de IA; token interno para `/analyze`.
- `heartbeat`, `regenerate` e `kill` respondem de forma uniforme e têm limite por IP e por identidade.

### Novas defesas
- Trava de sessão por nível de paranoia, com desafio MFA (TOTP) e bloqueio progressivo.
- Detecção de reuso de token rotacionado (sinal de roubo): a identidade é destruída e o dono é avisado.
- Modo agente: concessões com escopo, prazo e limite de usos, aprovação humana por TOTP, aprovação por ação sensível, revogação e auditoria.
- Chamadas do servidor do cliente repassam IP e navegador do usuário final e são limitadas pelo plano da chave de API.

### Desenvolvedor
- SDK TypeScript (`sdk/`), especificação OpenAPI (`docs/openapi.yaml`) e guia de integração.
- ESLint, Prettier, Husky, testes (Vitest) e `npm audit` no CI.
