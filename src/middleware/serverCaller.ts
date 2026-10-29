import net from 'net';
import { NextFunction, Request, Response } from 'express';
import { ApiKey, validateApiKey } from '../services/apiKeyService';
import { getClientIp } from '../utils/clientIp';
import { isBlocked, recordFailure } from '../utils/failureLimiter';

/**
 * Chamador servidor-a-servidor nas rotas /identity.
 *
 * Quando o SERVIDOR do cliente chama a Rekuway em nome de um usuário, a conexão
 * vem do IP do servidor, e o IP e o navegador que importam são os do usuário.
 * Se a requisição traz uma chave de API válida (`Authorization: Bearer rkwy_live_…`),
 * ela pode repassar esse contexto:
 *
 *   x-end-user-ip          IP do usuário final
 *   x-end-user-user-agent  navegador do usuário final
 *
 * Os cabeçalhos só valem com chave válida: sem ela são ignorados (qualquer um
 * poderia forjá-los). Uma chave inválida não gera erro (a resposta uniforme
 * continua), mas conta como falha de autenticação do IP e, passado o limite,
 * deixamos de consultar o Redis a cada tentativa.
 */
export interface ServerCaller {
  apiKey: ApiKey;
  /** IP do usuário final, se repassado e válido. */
  endUserIp?: string;
  userAgent?: string;
}

declare module 'express-serve-static-core' {
  interface Request {
    serverCaller?: ServerCaller;
  }
}

export const INVALID_KEY_ATTEMPTS_PER_IP = 20;
const MAX_UA_LENGTH = 256;

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim();

export function parseEndUserContext(headers: Request['headers']) {
  const ip = first(headers['x-end-user-ip']);
  const ua = first(headers['x-end-user-user-agent']);
  return {
    endUserIp: ip && net.isIP(ip) !== 0 ? ip : undefined,
    userAgent: ua ? ua.slice(0, MAX_UA_LENGTH) : undefined,
  };
}

export async function resolveServerCaller(req: Request, _res: Response, next: NextFunction) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!bearer) return next();

  const failKey = `identauthfail:${getClientIp(req)}`;
  try {
    if (await isBlocked(failKey, INVALID_KEY_ATTEMPTS_PER_IP)) return next();
    const apiKey = await validateApiKey(bearer);
    if (!apiKey) {
      await recordFailure(failKey, 60);
      return next();
    }
    req.serverCaller = { apiKey, ...parseEndUserContext(req.headers) };
  } catch {
    // Sem como validar a chave: segue como anônimo (limites por IP e fail-closed valem).
  }
  next();
}

/** IP a considerar: o do usuário final (se o servidor autenticado o repassou) ou o da conexão. */
export function callerIp(req: Request): string {
  return req.serverCaller?.endUserIp ?? getClientIp(req);
}

export function callerUserAgent(req: Request): string {
  return req.serverCaller?.userAgent ?? String(req.headers['user-agent'] || '');
}

/** Chave de API válida, mas sem IP de usuário repassado: o IP da conexão é do servidor. */
export function isServerWithoutEndUserIp(req: Request): boolean {
  return !!req.serverCaller && !req.serverCaller.endUserIp;
}
