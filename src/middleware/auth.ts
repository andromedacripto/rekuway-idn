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
//  FAKE METADATA — infra realista
//  Mistura AWS / GCP / Cloudflare propositalmente
//  para dificultar fingerprint de vendor
// ─────────────────────────────────────────────
const FAKE_INFRA = {
  providers: [
    { provider: 'aws',        regions: ['us-east-1','us-west-2','eu-west-1','ap-southeast-1','sa-east-1'] },
    { provider: 'gcp',        regions: ['us-central1','europe-west1','asia-east1','southamerica-east1'] },
    { provider: 'cloudflare', regions: ['GRU','GIG','EWR','LHR','SIN','NRT'] },
  ],
  gateways : ['edge-a1','edge-b2','core-mx3','proxy-r4','lb-f5','ingress-g6'],
  reasons  : [
    'constraint_violation',
    'policy_mismatch',
    'quota_exceeded',
    'session_expired',
    'token_rotation',
    'geo_restriction',
    'account_suspended',
    'invalid_scope',
  ],
};

function fakeMetadata() {
  const infra   = FAKE_INFRA.providers[Math.floor(Math.random() * FAKE_INFRA.providers.length)];
  const region  = infra.regions [Math.floor(Math.random() * infra.regions.length)];
  const gateway = FAKE_INFRA.gateways[Math.floor(Math.random() * FAKE_INFRA.gateways.length)];
  const reason  = FAKE_INFRA.reasons [Math.floor(Math.random() * FAKE_INFRA.reasons.length)];

  // latência coerente: cloudflare < gcp < aws (realismo)
  const baseLatency = infra.provider === 'cloudflare' ? 8
                    : infra.provider === 'gcp'        ? 18
                    :                                   32;
  const latency = baseLatency + Math.floor(Math.random() * 15);

  return {
    request_id : crypto.randomUUID(),
    provider   : infra.provider,
    region,
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
