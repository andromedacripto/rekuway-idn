/**
 * Rekuway IDN: SDK TypeScript (sem dependências, Node 18+ e navegadores).
 *
 * A API responde a qualquer falha com o mesmo corpo uniforme (modo "stealth").
 * O SDK traduz as respostas em resultados tipados e cuida da rotação de token:
 * use `RekuwaySession` e você nunca precisa guardar o token novo à mão.
 *
 *   const rk = new Rekuway({ baseUrl: 'https://api.exemplo.com', apiKey: process.env.RKWY_API_KEY });
 *   const { session, mfa } = await rk.createSession('high');   // mostre `mfa` ao usuário UMA vez
 *   const result = await session.check();
 *   if (result.status === 'step_up_required') await session.stepUp(codigoDoApp);
 */

export type ParanoiaLevel = 'low' | 'medium' | 'high' | 'deadman';

export interface RekuwayOptions {
  baseUrl: string;
  /** Chave `rkwy_live_…`. Necessária só para criar identidades. */
  apiKey?: string;
  /** Padrão 10 s. */
  timeoutMs?: number;
  /** Cabeçalhos extras em toda requisição. */
  headers?: Record<string, string>;
  /** Injeção de `fetch` (testes, runtimes antigos). */
  fetch?: typeof fetch;
}

export interface MfaEnrollment {
  /** Segredo TOTP em base32. Exibido uma única vez. */
  secret: string;
  /** URI otpauth:// para gerar o QR code. */
  otpauthUri: string;
}

export interface IdentitySummary {
  id: string;
  publicKey?: string;
  paranoiaLevel: ParanoiaLevel;
  expiresAt: number;
}

/**
 * Contexto do usuário final. Use quando o SEU SERVIDOR chama a Rekuway em nome
 * de um usuário: sem isso a Rekuway enxerga o IP e o navegador do seu servidor,
 * e o risco por "IP novo" ou "navegador diferente" perde o valor.
 * Só é considerado quando o cliente foi criado com `apiKey`.
 */
export interface EndUserContext {
  ip?: string;
  userAgent?: string;
}

export type Credentials = { token: string } | { identityId: string; privateKey: string };

export type CheckResult =
  | { status: 'allowed'; token?: string; identity: IdentitySummary }
  /** Risco detectado: a sessão foi travada. Peça o código MFA e chame `stepUp`. */
  | { status: 'step_up_required'; challengeId: string; methods: Array<'reauth' | 'mfa'> }
  /** Desafios falharam repetidamente: sessão bloqueada por um tempo. */
  | { status: 'blocked'; retryAfterSeconds: number }
  /**
   * Resposta uniforme: credencial inválida, identidade destruída ou expirada,
   * limite excedido. A API não diz qual; é proposital.
   */
  | { status: 'denied' };

export type StepUpResult =
  | { status: 'allowed'; token?: string; identity: IdentitySummary }
  | { status: 'failed'; remainingAttempts: number }
  | { status: 'blocked'; retryAfterSeconds: number }
  | { status: 'denied' };

export class RekuwayError extends Error {
  constructor(
    message: string,
    readonly httpStatus?: number,
    /** Código da API (ex.: invalid_code, locked, not_found). */
    readonly code?: string
  ) {
    super(message);
    this.name = 'RekuwayError';
  }
}

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null;

export class Rekuway {
  private readonly base: string;
  private readonly doFetch: typeof fetch;

  constructor(private readonly opts: RekuwayOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, '');
    this.doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private async post(
    path: string,
    body: unknown,
    bearer?: string,
    context?: EndUserContext
  ): Promise<Json> {
    let res: Response;
    try {
      res = await this.doFetch(`${this.base}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
          ...(bearer && context?.ip ? { 'x-end-user-ip': context.ip } : {}),
          ...(bearer && context?.userAgent ? { 'x-end-user-user-agent': context.userAgent } : {}),
          ...this.opts.headers,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000),
      });
    } catch (error) {
      throw new RekuwayError(`network error: ${(error as Error).message}`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      json = {};
    }
    return isObj(json) ? json : {};
  }

  /** Modo agente: credenciais com escopo, aprovadas por um humano. Exige `apiKey`. */
  readonly agents = new RekuwayAgents(this);

  /** Chamada às rotas /agents (erros explícitos: `{ ok:false, error }`). Uso interno. */
  async call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Json> {
    if (!this.opts.apiKey) throw new RekuwayError('apiKey is required for agent access');
    let res: Response;
    try {
      res = await this.doFetch(`${this.base}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.opts.apiKey}`,
          ...this.opts.headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000),
      });
    } catch (error) {
      throw new RekuwayError(`network error: ${(error as Error).message}`);
    }
    const json = (await res.json().catch(() => ({}))) as Json;
    if (json.ok === false && isObj(json.error)) {
      throw new RekuwayError(String(json.error.message), res.status, String(json.error.code));
    }
    if (!res.ok) throw new RekuwayError(`unexpected response (${res.status})`, res.status);
    return json;
  }

  /** Cria uma identidade. Exige `apiKey`. */
  async createIdentity(
    level: ParanoiaLevel = 'medium',
    options: { externalRef?: string } = {}
  ): Promise<{ token: string; expiresAt: number; mfa?: MfaEnrollment }> {
    if (!this.opts.apiKey) throw new RekuwayError('apiKey is required to create identities');
    const body = await this.post(
      '/identity/new',
      {
        paranoiaLevel: level,
        ...(options.externalRef ? { externalRef: options.externalRef } : {}),
      },
      this.opts.apiKey
    );
    if (body.status !== 'created' || typeof body.token !== 'string') {
      throw new RekuwayError(
        'identity was not created (invalid key, limit reached or server busy)'
      );
    }
    const mfa = isObj(body.mfa)
      ? { secret: String(body.mfa.secret), otpauthUri: String(body.mfa.otpauthUri) }
      : undefined;
    return { token: body.token, expiresAt: Number(body.expiresAt), ...(mfa ? { mfa } : {}) };
  }

  /** Cria a identidade e já devolve uma sessão que rotaciona o token sozinha. */
  async createSession(level: ParanoiaLevel = 'medium', options: { externalRef?: string } = {}) {
    const { token, expiresAt, mfa } = await this.createIdentity(level, options);
    return { session: new RekuwaySession(this, token), expiresAt, mfa };
  }

  /**
   * Desligamento: destrói todas as identidades vivas de uma pessoa (o `externalRef`
   * usado ao criá-las). Exige `apiKey`. Devolve quantas identidades foram destruídas.
   * Isto encerra as sessões da Rekuway; o login no seu sistema continua sendo seu.
   */
  async revokePerson(externalRef: string): Promise<{ revoked: number }> {
    const body = await this.call('POST', '/identity/people/revoke', { externalRef });
    return { revoked: Number(body.revoked ?? 0) };
  }

  async check(credentials: Credentials, context?: EndUserContext): Promise<CheckResult> {
    return parseCheck(await this.post('/identity/check', credentials, this.opts.apiKey, context));
  }

  async stepUp(
    credentials: Credentials,
    challengeId: string,
    code?: string,
    context?: EndUserContext
  ): Promise<StepUpResult> {
    const body = await this.post(
      '/identity/step-up',
      { ...credentials, challengeId, ...(code ? { code } : {}) },
      this.opts.apiKey,
      context
    );
    if (body.action === 'STEP_UP_FAILED') {
      return { status: 'failed', remainingAttempts: Number(body.remainingAttempts) };
    }
    return parseCheck(body) as StepUpResult;
  }

  /** Renova o prazo de uma identidade `deadman` (exige a chave privada). */
  async heartbeat(
    identityId: string,
    privateKey: string,
    context?: EndUserContext
  ): Promise<boolean> {
    const body = await this.post(
      '/identity/heartbeat',
      { identityId, privateKey },
      this.opts.apiKey,
      context
    );
    return body.success === true && isObj(body.identity);
  }

  /** Troca por uma identidade nova. Devolve a credencial (guarde-a). */
  async regenerate(identityId: string, privateKey: string, context?: EndUserContext) {
    const body = await this.post(
      '/identity/regenerate',
      { identityId, privateKey },
      this.opts.apiKey,
      context
    );
    if (typeof body.token !== 'string' || body.mode === 'stealth') return null;
    const payload = JSON.parse(decodeBase64Url(body.token)) as { i: string; k: string };
    return {
      identityId: payload.i,
      privateKey: payload.k,
      expiresAt: Number(body.exp),
      level: String(body.lvl) as ParanoiaLevel,
    };
  }

  /** Destrói a identidade. `true` só se a API confirmou. */
  async kill(identityId: string, privateKey: string, context?: EndUserContext): Promise<boolean> {
    const body = await this.post(
      '/identity/kill',
      { identityId, privateKey },
      this.opts.apiKey,
      context
    );
    return body.success === true && body.mode === undefined;
  }
}

/** Guarda o token atual e o troca por si só a cada resposta bem-sucedida. */
export class RekuwaySession {
  private current: string;
  private lastChallenge?: string;

  constructor(
    private readonly client: Rekuway,
    token: string
  ) {
    this.current = token;
  }

  /** Token atual. Persista-o se a sessão precisar sobreviver a um reinício. */
  get token(): string {
    return this.current;
  }

  async check(context?: EndUserContext): Promise<CheckResult> {
    const result = await this.client.check({ token: this.current }, context);
    if (result.status === 'allowed' && result.token) this.current = result.token;
    if (result.status === 'step_up_required') this.lastChallenge = result.challengeId;
    return result;
  }

  /** Responde ao desafio pendente com o código do autenticador. */
  async stepUp(
    code?: string,
    challengeId = this.lastChallenge,
    context?: EndUserContext
  ): Promise<StepUpResult> {
    if (!challengeId) throw new RekuwayError('no pending challenge: call check() first');
    const result = await this.client.stepUp({ token: this.current }, challengeId, code, context);
    if (result.status === 'allowed') {
      if (result.token) this.current = result.token;
      this.lastChallenge = undefined;
    }
    return result;
  }
}

function parseCheck(body: Json): CheckResult {
  switch (body.action) {
    case 'ALLOWED': {
      const id = isObj(body.identity) ? body.identity : {};
      return {
        status: 'allowed',
        ...(typeof body.token === 'string' ? { token: body.token } : {}),
        identity: {
          id: String(id.id),
          ...(typeof id.publicKey === 'string' ? { publicKey: id.publicKey } : {}),
          paranoiaLevel: String(id.paranoiaLevel) as ParanoiaLevel,
          expiresAt: Number(id.expiresAt),
        },
      };
    }
    case 'STEP_UP_REQUIRED':
      return {
        status: 'step_up_required',
        challengeId: String(body.challengeId),
        methods: Array.isArray(body.methods)
          ? (body.methods as Array<'reauth' | 'mfa'>)
          : ['reauth'],
      };
    case 'BLOCKED':
      return { status: 'blocked', retryAfterSeconds: Number(body.retryAfter) };
    default:
      return { status: 'denied' };
  }
}

function decodeBase64Url(input: string): string {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

// ───────────────────────────────────────────────────────────────
//  Modo agente
// ───────────────────────────────────────────────────────────────

export type AgentDenyReason =
  | 'invalid_token'
  | 'expired'
  | 'revoked'
  | 'scope_denied'
  | 'rate_limited'
  | 'limit_reached'
  | 'approval_required'
  | 'approval_pending'
  | 'approval_invalid'
  | 'unavailable';

export type AgentVerifyResult =
  | {
      allowed: true;
      grantId: string;
      agentId: string;
      remainingUses: number | null;
      expiresAt: number;
    }
  | { allowed: false; reason: AgentDenyReason; approvalId?: string; approvalExpiresAt?: number };

export interface AgentGrant {
  id: string;
  agentId: string;
  approverId: string;
  scopes: string[];
  sensitiveScopes: string[];
  maxUses: number | null;
  createdAt: number;
  expiresAt: number;
  status: 'active' | 'expired' | 'revoked';
}

export interface AccessRequestInput {
  agentId: string;
  approverId: string;
  /** Ex.: ['db:read', 'files:*']. Curinga só no final; "*" sozinho não existe. */
  scopes: string[];
  /** Subconjunto de `scopes` que exige aprovação humana a cada uso. */
  sensitiveScopes?: string[];
  /** 60 a 86400 s. Padrão 3600. */
  ttlSeconds?: number;
  maxUses?: number;
  reason?: string;
}

/**
 * Fluxo: createApprover -> requestAccess -> (humano digita o código) approve
 * -> o agente usa o token; o SEU servidor chama verify() a cada uso -> revoke().
 * Estes métodos lançam RekuwayError (com `code`) em erros de uso; "negado" em
 * verify() NÃO é erro: vem em { allowed: false, reason }.
 */
export class RekuwayAgents {
  constructor(private readonly rk: Rekuway) {}

  /** Cadastra quem aprova. Mostre `mfa` (QR do otpauthUri) uma única vez. */
  async createApprover(approverId: string): Promise<{ approverId: string; mfa: MfaEnrollment }> {
    const r = await this.rk.call('POST', '/agents/approvers', { approverId });
    return { approverId: String(r.approverId), mfa: r.mfa as MfaEnrollment };
  }

  async requestAccess(
    input: AccessRequestInput
  ): Promise<{ requestId: string; expiresAt: number }> {
    const r = await this.rk.call('POST', '/agents/access-requests', input);
    return { requestId: String(r.requestId), expiresAt: Number(r.expiresAt) };
  }

  async getRequest(requestId: string) {
    const r = await this.rk.call('GET', `/agents/access-requests/${requestId}`);
    return {
      requestId: String(r.requestId),
      status: r.status as 'pending' | 'approved' | 'denied',
      grantId: (r.grantId as string | null) ?? null,
    };
  }

  /** O humano aprova com o código do celular. O token só aparece aqui, uma vez. */
  async approve(requestId: string, code: string): Promise<{ token: string; grant: AgentGrant }> {
    const r = await this.rk.call('POST', `/agents/access-requests/${requestId}/approve`, { code });
    return { token: String(r.token), grant: r.grant as AgentGrant };
  }

  async deny(requestId: string): Promise<void> {
    await this.rk.call('POST', `/agents/access-requests/${requestId}/deny`, {});
  }

  /** O agente pode executar `action` agora? Chame a cada uso, no seu servidor. */
  async verify(token: string, action: string, options: { approvalId?: string } = {}) {
    const r = await this.rk.call('POST', '/agents/verify', { token, action, ...options });
    const result = { ...r };
    delete result.ok;
    return result as unknown as AgentVerifyResult;
  }

  /** O humano aprova uma ação sensível pendente com o código do celular. */
  async approveAction(approvalId: string, code: string) {
    const r = await this.rk.call('POST', `/agents/approvals/${approvalId}/approve`, { code });
    return { action: String(r.action), grantId: String(r.grantId) };
  }

  async getGrant(grantId: string): Promise<AgentGrant> {
    return (await this.rk.call('GET', `/agents/grants/${grantId}`)).grant as AgentGrant;
  }

  async audit(grantId: string, limit = 50) {
    const r = await this.rk.call('GET', `/agents/grants/${grantId}/audit?limit=${limit}`);
    return r.entries as Array<{
      at: number;
      action: string;
      result: 'allowed' | 'denied';
      reason?: string;
    }>;
  }

  /** Botão de pânico: o acesso do agente acaba na hora. */
  async revoke(grantId: string): Promise<void> {
    await this.rk.call('POST', `/agents/grants/${grantId}/revoke`, {});
  }
}

// ── Middleware (Express e similares) ──────────────────────────
interface GuardReq {
  headers: Record<string, string | string[] | undefined>;
  agent?: { grantId: string; agentId: string };
}
interface GuardRes {
  status(code: number): GuardRes;
  json(body: unknown): unknown;
}

/**
 * Protege uma rota do SEU servidor: só passa se o agente (token `agt_…` no
 * header Authorization) tem permissão para `action`.
 *   - ação sensível sem aprovação: 202 { error:'approval_required', approvalId }
 *   - o agente repete a chamada com o header `x-approval-id` depois que o humano aprovar
 */
export function agentGuard(rk: Rekuway, action: string) {
  return async (req: GuardReq, res: GuardRes, next: () => void) => {
    const auth = String(req.headers.authorization ?? '');
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'missing_token' });
    const approvalId = String(req.headers['x-approval-id'] ?? '') || undefined;
    let result: AgentVerifyResult;
    try {
      result = await rk.agents.verify(token, action, { approvalId });
    } catch {
      return res.status(503).json({ error: 'access_check_unavailable' }); // na dúvida, nega
    }
    if (result.allowed) {
      req.agent = { grantId: result.grantId, agentId: result.agentId };
      return next();
    }
    if (result.reason === 'approval_required' || result.reason === 'approval_pending') {
      return res.status(202).json({ error: result.reason, approvalId: result.approvalId });
    }
    const status =
      result.reason === 'invalid_token' ? 401 : result.reason === 'rate_limited' ? 429 : 403;
    return res.status(status).json({ error: result.reason });
  };
}
