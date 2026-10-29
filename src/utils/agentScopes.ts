/**
 * Escopos de acesso de agentes: "recurso:ação", com curinga só no final.
 *   db:read          exato
 *   db:*             qualquer ação em db
 *   db:orders:*      qualquer ação em db:orders
 * Um "*" sozinho é proibido: acesso total não é um escopo.
 */
const SCOPE_RE = /^[a-z0-9][a-z0-9_.-]{0,31}(?::[a-z0-9_.-]{1,32}){0,3}(?::\*)?$/;
export const MAX_SCOPES = 20;
export const MAX_SCOPE_LENGTH = 64;

export function isScope(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_SCOPE_LENGTH && SCOPE_RE.test(value);
}

/** Ação concreta (o que o agente quer fazer agora): sem curinga. */
export function isAction(value: unknown): value is string {
  return isScope(value) && !value.endsWith('*');
}

/** `pattern` cobre `target`? (igual, ou curinga final cobrindo o prefixo) */
export function patternCovers(pattern: string, target: string): boolean {
  if (pattern === target) return true;
  if (!pattern.endsWith(':*')) return false;
  const prefix = pattern.slice(0, -1); // "db:"
  return target.startsWith(prefix) && target.length > prefix.length;
}

export function scopeAllows(granted: readonly string[], action: string): boolean {
  return granted.some((p) => patternCovers(p, action));
}

/** Devolve a mensagem de erro, ou null se a lista é válida. */
export function validateScopes(list: unknown, label = 'scopes'): string | null {
  if (!Array.isArray(list) || list.length === 0) return `${label} must be a non-empty array`;
  if (list.length > MAX_SCOPES) return `${label} accepts at most ${MAX_SCOPES} entries`;
  if (!list.every(isScope))
    return `${label} contains an invalid scope (use resource:action, wildcard only at the end)`;
  if (new Set(list).size !== list.length) return `${label} contains duplicates`;
  return null;
}

/** Cada escopo sensível precisa estar dentro do que foi concedido. */
export function sensitiveWithinGranted(granted: readonly string[], sensitive: readonly string[]) {
  return sensitive.every((s) => granted.some((g) => patternCovers(g, s)));
}
