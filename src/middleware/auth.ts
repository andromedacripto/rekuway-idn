import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { validateApiKey, checkRateLimit, incrementBlockedRequests, ApiKey } from '../services/apiKeyService';

// Extende Request pra incluir apiKey
declare global {
  namespace Express {
    interface Request {
      apiKey?: ApiKey;
    }
  }
}

// ─────────────────────────────────────────────
//  HONEYPOT CONFIG
//  Keys que ativam modo de coleta silenciosa.
//  Coloque aqui keys "vazadas" propositalmente
//  em repositórios públicos, pastes, etc.
// ─────────────────────────────────────────────
const HONEYPOT_KEYS = new Set([
  'rkwy_live_honeypot_001',
  'rkwy_live_honeypot_002',
  // adicione quantas quiser
]);

// ─────────────────────────────────────────────
//  FAKE METADATA — máxima variabilidade
//  Regras:
//  - providers misturados incluindo edge/cdn genéricos
//  - zonas opacas (cluster-N, node-N) sem semântica geográfica óbvia
//  - reasons neutros: não revelam lógica interna
//  - latência coerente com o delay real aplicado (80–220ms)
// ─────────────────────────────────────────────
const FAKE_INFRA = {
  providers: [
    // providers reais — variam o vendor fingerprintado
    { provider: 'aws',   zones: ['cluster-3','cluster-11','cluster-19','cluster-27','cluster-34'] },
    { provider: 'azure', zones: ['cluster-5','cluster-14','cluster-22','cluster-38','cluster-41'] },
    { provider: 'gcp',   zones: ['cluster-2','cluster-9','cluster-17','cluster-29','cluster-45'] },
    // providers opacos — sem referência geográfica
    { provider: 'edge',  zones: ['node-7','node-13','node-21','node-33','node-50'] },
    { provider: 'cdn-x', zones: ['node-4','node-18','node-26','node-37','node-44'] },
  ],
  gateways : [
    'gw-c1','gw-f2','gw-a3','gw-d4','gw-b5',
    'gw-e6','gw-h7','gw-g8','gw-i9','gw-j10',
  ],
  // reasons neutros — não revelam lógica de auth
  reasons: ['processed','handled','accepted','ok','completed','forwarded','routed','dispatched'],
};

// Marcador de tempo do início do delay — exportado internamente pra latência coerente
let _requestStart = 0;

function fakeMetadata() {
  const infra   = FAKE_INFRA.providers[Math.floor(Math.random() * FAKE_INFRA.providers.length)];
  const zone    = infra.zones   [Math.floor(Math.random() * infra.zones.length)];
  const gateway = FAKE_INFRA.gateways[Math.floor(Math.random() * FAKE_INFRA.gateways.length)];
  const reason  = FAKE_INFRA.reasons [Math.floor(Math.random() * FAKE_INFRA.reasons.length)];

  // latência coerente: reflete o tempo real decorrido desde o início do delay
  const elapsed   = _requestStart > 0 ? Date.now() - _requestStart : 80 + Math.floor(Math.random() * 60);
  const latency   = elapsed + Math.floor(Math.random() * 8); // leve ruído em cima do real

  return {
    request_id : crypto.randomUUID(),
    provider   : infra.provider,
    zone,
    gateway,
    reason,
    latency_ms : latency,
    ts         : Date.now() - latency,
  };
}

// ─────────────────────────────────────────────
//  TIMING — jitter não-linear (distribuição beta)
//  80–220ms, sem pico fixo identificável
// ─────────────────────────────────────────────
function nonLinearJitter(): Promise<void> {
  const u1   = Math.random();
  const u2   = Math.random();
  const beta = u1 * u1 * (1 - u2 * u2); // skewed, não uniforme
  const delay = Math.floor(80 + beta * 140); // 80–220ms
  return new Promise(resolve => setTimeout(resolve, delay));
}

// ─────────────────────────────────────────────
//  ESTRUTURAS DE RESPOSTA — rotação aleatória
//  Impede fingerprint por shape de JSON
// ─────────────────────────────────────────────
type AuthFailShape = 'unauthorized' | 'ghost_ok' | 'processed';

function pickFailShape(): AuthFailShape {
  const r = Math.random();
  if (r < 0.05) return 'ghost_ok';   //  5% → parece sucesso (confunde)
  if (r < 0.10) return 'processed';  //  5% → shape alternativa
  return 'unauthorized';             // 90% → shape padrão
}

function buildFailResponse(shape: AuthFailShape) {
  const meta = fakeMetadata();
  switch (shape) {
    case 'ghost_ok':   return { status: 'ok',        meta };
    case 'processed':  return { processed: true,     meta };
    default:           return { success: false, error: 'Unauthorized', meta };
  }
}

// ─────────────────────────────────────────────
//  HONEYPOT — coleta silenciosa
//  Simula sucesso e loga tudo do atacante
// ─────────────────────────────────────────────
function logHoneypotHit(req: Request, apiKeyString: string) {
  const payload = {
    event      : 'HONEYPOT_HIT',
    ts         : new Date().toISOString(),
    key        : apiKeyString,
    ip         : req.ip || req.socket?.remoteAddress,
    user_agent : req.headers['user-agent'],
    method     : req.method,
    path       : req.path,
    query      : req.query,
    headers    : {
      origin      : req.headers['origin'],
      referer     : req.headers['referer'],
      accept_lang : req.headers['accept-language'],
    },
  };
  // Em produção: enviar para SIEM / Datadog / Sentry
  console.warn('[HONEYPOT]', JSON.stringify(payload));
}

// ─────────────────────────────────────────────
//  MIDDLEWARE PRINCIPAL
// ─────────────────────────────────────────────
export async function requireApiKey(req: Request, res: Response, next: NextFunction) {
  try {
    _requestStart = Date.now();
    await nonLinearJitter();

    const authHeader  = req.headers.authorization;
    const queryApiKey = req.query.apiKey as string;

    let apiKeyString: string | null = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      apiKeyString = authHeader.substring(7);
    } else if (queryApiKey) {
      apiKeyString = queryApiKey;
    }

    // ── Key ausente ──────────────────────────
    if (!apiKeyString) {
      const shape = pickFailShape();
      return res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
    }

    // ── Honeypot hit ─────────────────────────
    if (HONEYPOT_KEYS.has(apiKeyString)) {
      logHoneypotHit(req, apiKeyString);
      return res.status(200).json({ status: 'ok', meta: fakeMetadata() });
    }

    // Valida API key
    const apiKey = await validateApiKey(apiKeyString);

    // ── Key inválida / revogada ───────────────
    if (!apiKey) {
      if (apiKeyString.startsWith('rkwy_live_')) {
        await incrementBlockedRequests(apiKeyString).catch(() => {});
      }
      const shape = pickFailShape();
      return res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
    }

    // Verifica rate limit
    const rateLimitCheck = await checkRateLimit(apiKey, false);

    if (!rateLimitCheck.allowed) {
      const shape = pickFailShape();
      return res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
    }

    req.apiKey = apiKey;

    res.setHeader('X-RateLimit-Limit',     apiKey.rateLimit.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Remaining', rateLimitCheck.limits.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Reset',     new Date(apiKey.usage.lastRequest + 60000).toISOString());

    next();

  } catch (error) {
    console.error('[AUTH] Error validating API key:', error);
    const shape = pickFailShape();
    res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
  }
}

// ─────────────────────────────────────────────
//  MIDDLEWARE DE IDENTIDADE
// ─────────────────────────────────────────────
export async function checkIdentityCreationLimit(req: Request, res: Response, next: NextFunction) {
  try {
    const apiKey = req.apiKey;

    if (!apiKey) {
      const shape = pickFailShape();
      return res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
    }

    const rateLimitCheck = await checkRateLimit(apiKey, true);

    if (!rateLimitCheck.allowed) {
      const shape = pickFailShape();
      return res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
    }

    res.setHeader('X-Identities-Limit',     apiKey.rateLimit.identitiesPerMonth.toString());
    res.setHeader('X-Identities-Remaining', rateLimitCheck.limits.identitiesRemaining.toString());
    res.setHeader('X-Identities-Reset',     new Date(apiKey.usage.resetDate).toISOString());

    next();

  } catch (error) {
    console.error('[AUTH] Error checking identity limit:', error);
    const shape = pickFailShape();
    res.status(shape === 'unauthorized' ? 401 : 200).json(buildFailResponse(shape));
  }
}
