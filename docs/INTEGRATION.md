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

## Agentes de IA

Para entregar a um agente de IA um acesso **curto, limitado e aprovado por uma pessoa**. O fluxo e os endpoints estão no README e em `openapi.yaml`; aqui, o que muda no seu produto:

```ts
// 1. Uma vez por pessoa que aprova: mostre o QR (mfa.otpauthUri) e guarde o approverId.
const { mfa } = await rk.agents.createApprover('maria');

// 2. O agente pede acesso. A pessoa recebe o pedido na sua tela.
const { requestId } = await rk.agents.requestAccess({
  agentId: 'assistente-financeiro', approverId: 'maria',
  scopes: ['db:read', 'db:write'], sensitiveScopes: ['db:write'],
  ttlSeconds: 3600, maxUses: 500, reason: 'fechamento do mês',
});

// 3. A pessoa digita o código do celular na SUA tela. O token vai para o agente.
const { token, grant } = await rk.agents.approve(requestId, codigoDigitado);

// 4. No seu servidor, em cada rota que o agente pode chamar:
app.get('/orders',  agentGuard(rk, 'db:read'),  listOrders);
app.post('/orders', agentGuard(rk, 'db:write'), createOrder);
```

Quando a ação é **sensível**, o `agentGuard` responde `202 { error:'approval_required', approvalId }`. Mostre à pessoa "o agente quer fazer `db:write`", ela aprova com o código (`rk.agents.approveAction(approvalId, codigo)`) e o agente repete a chamada com o header `x-approval-id`. A aprovação vale **uma** chamada e expira em 5 minutos.

Boas práticas:
- **Escopos mínimos e prazo curto.** `db:read` por 1 hora é melhor que `db:*` por 24 horas.
- **Guarde só o `grant.id`**; o token sai uma vez e a Rekuway guarda apenas o hash dele.
- **Painel de revogação:** ofereça um botão que chama `rk.agents.revoke(grant.id)`.
- **Trilha de auditoria:** `rk.agents.audit(grant.id)` lista os usos permitidos e negados.
- **Aprovação por código:** cada código do celular só vale uma vez (muda a cada 30 s). Duas aprovações seguidas pedem dois códigos diferentes.

O que o modo agente **não** faz: não mede risco por IP (agentes mudam de IP o tempo todo), e o token é um segredo de portador: se vazar, vale até o prazo ou a revogação. Escopo, prazo, limite de usos e `revoke` limitam o estrago, mas não o impedem.

## Por pessoa: acompanhar e revogar no desligamento

Ao criar a identidade, passe um **código opaco da pessoa** (`externalRef`, por exemplo a matrícula `func-1042`). Ele não deve ser nome, e-mail nem CPF: quem associa o código ao nome é o seu dashboard.

```ts
const { session } = await rk.createSession('high', { externalRef: 'func-1042' });

// Desligamento (chamado pelo seu RH): destrói todas as identidades vivas da pessoa
const { revoked } = await rk.revokePerson('func-1042');
```

- Os eventos desta pessoa chegam ao dashboard com o código no `metadata.externalRef`, e o dashboard agrupa por ele.
- `revokePerson` encerra as sessões **da Rekuway**. Bloquear o e-mail, o Microsoft 365 ou o Google Workspace continua sendo uma ação do seu sistema ou do provedor.
- Cada empresa só alcança as próprias pessoas: o mesmo código em outra empresa não é afetado.
- Se a Rekuway regenerar uma identidade (REGENERATE), a nova continua ligada à mesma pessoa.

## Chamando do seu servidor: repasse o contexto do usuário

O risco por "IP novo" e "navegador diferente" usa o IP e o navegador de **quem chama a Rekuway**. Se o seu **servidor** chama em nome do usuário, a Rekuway só veria o IP do servidor. Por isso:

```ts
const rk = new Rekuway({ baseUrl, apiKey: process.env.RKWY_API_KEY });   // chave de API: só no servidor
const result = await session.check({
  ip: req.ip,                              // IP do usuário final (o do SEU servidor web, atrás do seu proxy confiável)
  userAgent: req.headers['user-agent'],
});
```

- O SDK envia `Authorization: Bearer <chave>` e os cabeçalhos `x-end-user-ip` e `x-end-user-user-agent`. **Sem chave de API válida esses cabeçalhos são ignorados** (qualquer um poderia forjá-los).
- **O limite deixa de ser por IP.** Com a chave, o tráfego conta contra o limite do seu **plano**; sem ela, vale 10 requisições por minuto por IP. Um backend inteiro sai de poucos IPs, então use a chave.
- **Se você não repassar o contexto**, o IP considerado é o do seu servidor e o sinal de "IP novo" não dispara (as outras defesas continuam).
- Você é responsável pela veracidade do IP que repassa: use o IP que o **seu** proxy confiável informa, nunca um cabeçalho que o usuário controla.
- Se a chamada vier direto do **navegador do usuário**, não use a chave de API (ela vazaria): chame sem chave e o IP real é o da conexão.

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

- **Auditoria dos agentes:** cada `verify` grava um registro por 30 dias. Para volumes muito altos, isso consome memória do Redis; ainda não foi medido.

- A IA é **consultiva** e foi treinada e medida só com dados sintéticos. As regras decidem.
- Nada aqui foi medido em carga. Não publique números de latência ou capacidade sem benchmark próprio.
- Não há conformidade certificada (SOC 2, ISO 27001). Isso é um passo da empresa, não do código.
