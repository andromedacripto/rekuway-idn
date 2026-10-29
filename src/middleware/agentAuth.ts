import { NextFunction, Request, Response } from 'express';
import { checkRateLimit, validateApiKey } from '../services/apiKeyService';
import { isBlocked, recordFailure } from '../utils/failureLimiter';
import { getClientIp } from '../utils/clientIp';

/**
 * Autenticação das rotas /agents: quem chama é o SERVIDOR do cliente, com a
 * chave de API (`Authorization: Bearer rkwy_live_…`). Diferente das rotas de
 * identidade, aqui os erros são explícitos: o chamador é um sistema que
 * precisa saber o que fez de errado.
 *
 * O limite global por IP não vale aqui (um backend inteiro sai de poucos IPs).
 * Em vez disso: falhas de autenticação por IP e o limite do plano por chave.
 */
export const AUTH_FAILURES_PER_IP = 20;

export async function requireAgentAuth(req: Request, res: Response, next: NextFunction) {
  const ip = getClientIp(req);
  const failKey = `agentauthfail:${ip}`;
  try {
    if (await isBlocked(failKey, AUTH_FAILURES_PER_IP)) {
      return res
        .status(429)
        .json({ ok: false, error: { code: 'rate_limited', message: 'too many failed attempts' } });
    }
    const header = req.headers.authorization || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
    const apiKey = bearer ? await validateApiKey(bearer) : null;
    if (!apiKey || !apiKey.userId) {
      await recordFailure(failKey, 60);
      return res
        .status(401)
        .json({ ok: false, error: { code: 'unauthorized', message: 'invalid API key' } });
    }
    const limit = await checkRateLimit(apiKey, false);
    if (!limit.allowed) {
      return res
        .status(429)
        .json({ ok: false, error: { code: 'rate_limited', message: 'plan rate limit exceeded' } });
    }
    req.apiKey = apiKey;
    next();
  } catch {
    // Fail-closed: sem Redis não há como autenticar.
    return res
      .status(503)
      .json({ ok: false, error: { code: 'unavailable', message: 'try again shortly' } });
  }
}
