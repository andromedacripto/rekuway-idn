/**
 * ============================================================
 * REKUWAY IDN — LOG SANITIZER
 * ============================================================
 *
 * Função global de sanitização de logs.
 * NUNCA loga dados sensíveis: privateKey, apiKey, tokens,
 * authorization headers ou qualquer secret.
 *
 * REGRA ABSOLUTA:
 *   - privateKey → [REDACTED]
 *   - apiKey / plainKey → [REDACTED]
 *   - authorization → [REDACTED]
 *   - token → [REDACTED]
 *   - password → [REDACTED]
 *   - secret → [REDACTED]
 *   - hashedKey → [REDACTED] (parcial, mostra 8 chars)
 *
 * USO:
 *   import { sanitize, safeLog, safeError, safeWarn } from '../utils/sanitize';
 *   safeLog('[TAG]', 'mensagem', objeto);
 */

const SENSITIVE_KEYS = new Set([
  'privateKey',
  'private_key',
  'apiKey',
  'api_key',
  'plainKey',
  'plain_key',
  'password',
  'passwd',
  'secret',
  'token',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'authorization',
  'Authorization',
  'credential',
  'credentials',
]);

const PARTIAL_REDACT_KEYS = new Set([
  'hashedKey',
  'hashed_key',
  'privateKeyHash',
]);

/**
 * Sanitiza recursivamente um objeto para remover dados sensíveis.
 * Seguro para uso em qualquer console.log / console.error.
 */
export function sanitize(data: unknown, depth = 0): unknown {
  // Limite de profundidade para evitar loops infinitos
  if (depth > 10) return '[MAX_DEPTH]';

  if (data === null || data === undefined) return data;

  // Strings: verifica se parece uma chave privada PEM ou JWT
  if (typeof data === 'string') {
    if (data.includes('-----BEGIN') || data.includes('-----END')) {
      return '[REDACTED:PEM]';
    }
    // JWT pattern: xxxxx.yyyyy.zzzzz
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(data)) {
      return '[REDACTED:JWT]';
    }
    return data;
  }

  if (typeof data !== 'object') return data;

  // Array
  if (Array.isArray(data)) {
    return data.map(item => sanitize(item, depth + 1));
  }

  // Error object
  if (data instanceof Error) {
    return {
      name: data.name,
      message: data.message,
      // Stack pode conter paths, mas não secrets — mantemos para debug
      stack: data.stack,
    };
  }

  // Objeto genérico
  const clone: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (SENSITIVE_KEYS.has(key)) {
      clone[key] = '[REDACTED]';
    } else if (PARTIAL_REDACT_KEYS.has(key) && typeof value === 'string') {
      // Mostra só os primeiros 8 chars do hash para debug
      clone[key] = `${value.substring(0, 8)}...[REDACTED]`;
    } else {
      clone[key] = sanitize(value, depth + 1);
    }
  }

  return clone;
}

/**
 * Sanitiza e serializa para log.
 * Converte objetos em JSON legível sem dados sensíveis.
 */
function formatForLog(args: unknown[]): unknown[] {
  return args.map(arg => {
    if (typeof arg === 'object' && arg !== null) {
      return sanitize(arg);
    }
    // String pura: verifica se parece PEM ou JWT
    if (typeof arg === 'string') {
      return sanitize(arg);
    }
    return arg;
  });
}

/**
 * console.log sanitizado — use sempre no lugar de console.log direto
 */
export function safeLog(tag: string, ...args: unknown[]): void {
  console.log(tag, ...formatForLog(args));
}

/**
 * console.error sanitizado — use sempre no lugar de console.error direto
 */
export function safeError(tag: string, ...args: unknown[]): void {
  console.error(tag, ...formatForLog(args));
}

/**
 * console.warn sanitizado — use sempre no lugar de console.warn direto
 */
export function safeWarn(tag: string, ...args: unknown[]): void {
  console.warn(tag, ...formatForLog(args));
}

/**
 * Sanitiza headers HTTP para log.
 * Remove Authorization, Cookie, e outros headers sensíveis.
 */
export function sanitizeHeaders(headers: Record<string, unknown>): Record<string, unknown> {
  const sensitiveHeaders = new Set([
    'authorization',
    'Authorization',
    'cookie',
    'Cookie',
    'x-api-key',
    'X-Api-Key',
    'x-auth-token',
    'X-Auth-Token',
  ]);

  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(headers)) {
    safe[key] = sensitiveHeaders.has(key) ? '[REDACTED]' : value;
  }
  return safe;
}