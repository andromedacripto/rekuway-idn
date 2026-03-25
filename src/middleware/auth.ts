import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { validateApiKey, checkRateLimit, incrementBlockedRequests, ApiKey } from '../services/apiKeyService';

declare global {
  namespace Express {
    interface Request {
      apiKey?: ApiKey;
    }
  }
}

// ─────────────────────────────────────────────
//  HONEYPOT CONFIG
//  Keys "vazadas" propositalmente em repos/pastes.
//  Quem usar entra em modo de coleta silenciosa.
// ─────────────────────────────────────────────
const HONEYPOT_KEYS = new Set([
  'rkwy_live_honeypot_001',
  'rkwy_live_honeypot_002',
]);

// ─────────────────────────────────────────────
//  RESPOSTA NORMALIZADA — API key inválida
//
//  REGRA ABSOLUTA: resposta única, sem variação,
//  sem campos extras, sem metadata.
//
//  Qualquer campo adicional é superfície de
//  fingerprint. fakeMetadata pertence ao LIE
//  layer (identidades), não ao layer de auth.
//
//  O atacante nunca deve distinguir:
//  - key ausente
//  - key inválida
//  - key revogada
//  - rate limit
//  - erro interno
// ─────────────────────────────────────────────
const AUTH_FAIL = Object.freeze({ success: false, error: 'Unauthorized' });

// ─────────────────────────────────────────────
//  TIMING — jitter não-linear
//  80–220ms, distribuição skewed (não uniforme).
//  Elimina timing oracle sem pico fixo identificável.
// ─────────────────────────────────────────────
function nonLinearJitter(): Promise<void> {
  const u1    = Math.random();
  const u2    = Math.random();
  const beta  = u1 * u1 * (1 - u2 * u2);
  const delay = Math.floor(80 + beta * 140);
  return new Promise(resolve => setTimeout(resolve, delay));
}

// ─────────────────────────────────────────────
//  HONEYPOT — coleta silenciosa
//  Simula sucesso, loga tudo do atacante.
//  Nunca revela que é honeypot.
// ─────────────────────────────────────────────
function logHoneypotHit(req: Request, key: string) {
  const payload = {
    event      : 'HONEYPOT_HIT',
    ts         : new Date().toISOString(),
    key,
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
    let   apiKeyString: string | null = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      apiKeyString = authHeader.substring(7);
    } else if (queryApiKey) {
      apiKeyString = queryApiKey;
    }

    // Key ausente → mesma resposta normalizada
    if (!apiKeyString) {
      return res.status(401).json(AUTH_FAIL);
    }

    // Honeypot hit → simula sucesso, loga atacante
    if (HONEYPOT_KEYS.has(apiKeyString)) {
      logHoneypotHit(req, apiKeyString);
      return res.status(200).json({ success: true });
    }

    const apiKey = await validateApiKey(apiKeyString);

    // Key inválida / revogada → mesma resposta normalizada
    if (!apiKey) {
      if (apiKeyString.startsWith('rkwy_live_')) {
        await incrementBlockedRequests(apiKeyString).catch(() => {});
      }
      return res.status(401).json(AUTH_FAIL);
    }

    const rateLimitCheck = await checkRateLimit(apiKey, false);

    // Rate limit → mesma resposta normalizada (não confirma que key existe)
    if (!rateLimitCheck.allowed) {
      return res.status(401).json(AUTH_FAIL);
    }

    req.apiKey = apiKey;

    res.setHeader('X-RateLimit-Limit',     apiKey.rateLimit.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Remaining', rateLimitCheck.limits.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Reset',     new Date(apiKey.usage.lastRequest + 60000).toISOString());

    next();

  } catch (error) {
    // Erro interno → mesma resposta normalizada, sem vazar stack
    console.error('[AUTH] Error validating API key:', error);
    res.status(401).json(AUTH_FAIL);
  }
}

// ─────────────────────────────────────────────
//  MIDDLEWARE DE IDENTIDADE
// ─────────────────────────────────────────────
export async function checkIdentityCreationLimit(req: Request, res: Response, next: NextFunction) {
  try {
    const apiKey = req.apiKey;

    if (!apiKey) {
      return res.status(401).json(AUTH_FAIL);
    }

    const rateLimitCheck = await checkRateLimit(apiKey, true);

    if (!rateLimitCheck.allowed) {
      return res.status(401).json(AUTH_FAIL);
    }

    res.setHeader('X-Identities-Limit',     apiKey.rateLimit.identitiesPerMonth.toString());
    res.setHeader('X-Identities-Remaining', rateLimitCheck.limits.identitiesRemaining.toString());
    res.setHeader('X-Identities-Reset',     new Date(apiKey.usage.resetDate).toISOString());

    next();

  } catch (error) {
    console.error('[AUTH] Error checking identity limit:', error);
    res.status(401).json(AUTH_FAIL);
  }
}
