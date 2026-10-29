# Guia de integração

Para quem vai colocar o Rekuway IDN na frente de um produto. O SDK TypeScript está em [`sdk/rekuway.ts`](../sdk/rekuway.ts) e o contrato HTTP em [`openapi.yaml`](openapi.yaml).

## Para que serve

O Rekuway IDN emite **identidades temporárias** (par de chaves, prazo curto, nível de paranoia) e protege cada uso delas. Ele faz sentido quando uma credencial roubada ou adivinhada custa caro:

| Cenário | Nível sugerido | Por quê |
| --- | --- | --- |
| Sessão de acesso a dados sensíveis (cofre, painel financeiro, prontuário) | `high` | Trava a sessão com MFA ao menor sinal de contexto estranho. |
| Link ou credencial compartilhada com terceiros por pouco tempo | `medium` | Expira sozinha e se defende de tentativas de adivinhar a chave. |
| Acesso de operador a produção, pessoas em situação de risco | `deadman` | Se o dono não der sinal de vida no prazo, a identidade é destruída. |
| Integração de baixo risco, só se quer expiração e limite | `low` | Menos atrito: a sessão só trava com risco alto. |

**O que ele não é:** não substitui o login do seu produto, nem um gestor de segredos, nem um WAF. Ele protege a *identidade temporária* que o seu produto emite.

## Fluxo em 4 passos

```ts
import { Rekuway } from './sdk/rekuway';

const rk = new Rekuway({ baseUrl: process.env.REKUWAY_URL!, apiKey: process.env.RKWY_API_KEY });

// 1. No backend: crie a identidade. Mostre o MFA ao usuário UMA vez (QR code do otpauthUri).
const { session, mfa } = await rk.createSession('high');

// 2. A cada uso, valide. O SDK troca o token sozinho: persista session.token.
const r = await session.check();

switch (r.status) {
  case 'allowed':
    break; // siga em frente
  case 'step_up_required': {
    // 3. Risco detectado: peça o código do autenticador e reautentique.
    const step = await session.stepUp(codigoDigitadoPeloUsuario);
    if (step.status === 'failed') mostrar(`Código errado. Restam ${step.remainingAttempts}.`);
    if (step.status === 'blocked') mostrar(`Bloqueado por ${step.retryAfterSeconds}s.`);
    break;
  }
  case 'blocked':
    mostrar(`Tente novamente em ${r.retryAfterSeconds}s ou procure o suporte.`);
    break;
  case 'denied':
    // 4. Credencial inválida, expirada ou destruída (a API não diz qual, de propósito).
    redirecionarParaLogin();
}
```

## O que seu produto precisa tratar

1. **Guardar o token novo.** A cada `allowed` o token muda. `RekuwaySession` faz isso; se você chamar a API direto, guarde o `token` da resposta.
2. **Mostrar o MFA uma vez.** `mfa.secret` e `mfa.otpauthUri` só vêm na criação.
3. **Tela de desafio.** Quando vier `step_up_required`, o usuário digita o código do autenticador. No nível `low` (sem MFA), `stepUp()` sem código só reapresenta a credencial.
4. **Suporte.** Usuário que perdeu o autenticador: o seu dashboard chama `POST /internal/identities/{id}/unlock` com `x-internal-secret`.
5. **`denied` depois de `allowed` = possível roubo.** Se um token que funcionava passa a ser negado, trate como incidente: peça uma identidade nova e investigue o evento `TOKEN_REUSE`. Chamadas **paralelas** com o mesmo token só são toleradas por 10 s após a troca; serialize as chamadas de uma mesma sessão (ou use um token por trabalhador).
6. **Não use o status HTTP.** Falhas voltam 200 com um corpo uniforme. O SDK já traduz.
7. **Deadman por token.** Quem só tem o token mantém a identidade viva chamando `check()` dentro do prazo (60 s no nível `deadman`).

## Eventos para o seu dashboard

A API envia (`POST {DASHBOARD_URL}/api/keys/event`, header `x-internal-secret`) eventos como `SESSION_LOCKED`, `SESSION_BLOCKED`, `SESSION_KILLED`, `SESSION_UNLOCKED`, `TOKEN_REUSE`, `ATTACK_BLOCKED` e `IDENTITY_ROTATION`. O seu dashboard deve **validar o `x-internal-secret`** e alertar a partir deles.

## Checklist de produção

- [ ] Variáveis do `.env.example` definidas (sobretudo `INTERNAL_SECRET`, `TOKEN_ENCRYPTION_KEY`, `ALLOWED_ORIGINS`).
- [ ] A API fica atrás da Vercel ou da Railway (o IP do cliente vem de `X-Real-IP`; exposta direto, ele é forjável).
- [ ] Agendador chamando `GET /internal/deadman-sweep` se for serverless.
- [ ] Alerta no log `[RATE_LIMIT] Redis indisponível` (com o Redis fora, as rotas sensíveis recusam).
- [ ] Teste de intrusão no ambiente real.
- [ ] Histórico do git limpo e credenciais antigas trocadas.

## Limites conhecidos

- A IA é **consultiva** e foi treinada e medida só com dados sintéticos. As regras decidem.
- Nada aqui foi medido em carga. Não publique números de latência ou capacidade sem benchmark próprio.
- Não há conformidade certificada (SOC 2, ISO 27001). Isso é um passo da empresa, não do código.
