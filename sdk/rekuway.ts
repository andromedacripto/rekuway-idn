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
    readonly httpStatus?: number
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

  private async post(path: string, body: unknown, bearer?: string): Promise<Json> {
    let res: Response;
    try {
      res = await this.doFetch(`${this.base}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
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

  /** Cria uma identidade. Exige `apiKey`. */
  async createIdentity(
    level: ParanoiaLevel = 'medium'
  ): Promise<{ token: string; expiresAt: number; mfa?: MfaEnrollment }> {
    if (!this.opts.apiKey) throw new RekuwayError('apiKey is required to create identities');
    const body = await this.post('/identity/new', { paranoiaLevel: level }, this.opts.apiKey);
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
  async createSession(level: ParanoiaLevel = 'medium') {
    const { token, expiresAt, mfa } = await this.createIdentity(level);
    return { session: new RekuwaySession(this, token), expiresAt, mfa };
  }

  async check(credentials: Credentials): Promise<CheckResult> {
    return parseCheck(await this.post('/identity/check', credentials));
  }

  async stepUp(
    credentials: Credentials,
    challengeId: string,
    code?: string
  ): Promise<StepUpResult> {
    const body = await this.post('/identity/step-up', {
      ...credentials,
      challengeId,
      ...(code ? { code } : {}),
    });
    if (body.action === 'STEP_UP_FAILED') {
      return { status: 'failed', remainingAttempts: Number(body.remainingAttempts) };
    }
    return parseCheck(body) as StepUpResult;
  }

  /** Renova o prazo de uma identidade `deadman` (exige a chave privada). */
  async heartbeat(identityId: string, privateKey: string): Promise<boolean> {
    const body = await this.post('/identity/heartbeat', { identityId, privateKey });
    return body.success === true && isObj(body.identity);
  }

  /** Troca por uma identidade nova. Devolve a credencial (guarde-a). */
  async regenerate(identityId: string, privateKey: string) {
    const body = await this.post('/identity/regenerate', { identityId, privateKey });
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
  async kill(identityId: string, privateKey: string): Promise<boolean> {
    const body = await this.post('/identity/kill', { identityId, privateKey });
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

  async check(): Promise<CheckResult> {
    const result = await this.client.check({ token: this.current });
    if (result.status === 'allowed' && result.token) this.current = result.token;
    if (result.status === 'step_up_required') this.lastChallenge = result.challengeId;
    return result;
  }

  /** Responde ao desafio pendente com o código do autenticador. */
  async stepUp(code?: string, challengeId = this.lastChallenge): Promise<StepUpResult> {
    if (!challengeId) throw new RekuwayError('no pending challenge: call check() first');
    const result = await this.client.stepUp({ token: this.current }, challengeId, code);
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
