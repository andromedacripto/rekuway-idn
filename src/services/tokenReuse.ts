import { db } from '../config/database';
import { killIdentity } from './identityService';
import { clearSession } from './sessionGuard';
import { notifyDashboard } from './dashboardEvents';
import { safeLog } from '../utils/sanitize';

/**
 * Detecção de reuso de token rotacionado.
 *
 * A cada uso válido o token é trocado por outro e o antigo morre. Se alguém
 * apresentar o token antigo depois, existem duas cópias do mesmo token em mãos
 * diferentes: o dono e um ladrão. Não dá para saber qual é qual, então a
 * resposta segura é destruir a identidade (o dono pede outra) e avisar.
 *
 * Retries e chamadas paralelas legítimas reaparecem com o token antigo logo
 * após a troca, por isso há uma janela de tolerância (REUSE_GRACE_MS).
 *
 * Só guardamos {identityId, instante}: nenhum segredo vai para a lápide.
 */
export const REUSE_GRACE_MS = 10_000;
const MAX_TOMBSTONE_TTL_S = 24 * 3600;

interface Tombstone {
  identityId: string;
  at: number;
}

const key = (token: string) => `extused:${token}`;

/** Chamar sempre que um token for trocado por outro. */
export async function recordRotation(
  oldToken: string,
  identityId: string,
  identityExpiresAt: number,
  now = Date.now()
): Promise<void> {
  const ttl = Math.max(
    1,
    Math.min(MAX_TOMBSTONE_TTL_S, Math.floor((identityExpiresAt - now) / 1000))
  );
  await db.set(key(oldToken), { identityId, at: now } satisfies Tombstone, ttl);
}

export type ReuseOutcome = 'none' | 'grace' | 'revoked';

/**
 * Chamar quando um token não resolveu para nenhuma credencial ativa.
 * - none: nunca foi rotacionado (token inválido comum);
 * - grace: reuso dentro da janela de tolerância (provável retry), nada é feito;
 * - revoked: reuso fora da janela, identidade destruída e dono avisado.
 */
export async function handleTokenReuse(
  token: string,
  context: { ip: string; userAgent: string },
  now = Date.now()
): Promise<ReuseOutcome> {
  const t = (await db.get(key(token))) as Tombstone | null;
  if (!t || typeof t !== 'object' || !t.identityId) return 'none';

  const ageMs = now - t.at;
  if (ageMs <= REUSE_GRACE_MS) return 'grace';

  const identity = await db.getIdentity(t.identityId);
  // Já destruída (por este mesmo evento ou outro): não repete o alerta.
  if (!identity || !identity.isAlive) return 'revoked';

  await killIdentity(t.identityId);
  await clearSession(t.identityId);
  safeLog('[TOKEN_REUSE] Rotated token presented again — identity destroyed', {
    identityId: t.identityId,
    ageSeconds: Math.round(ageMs / 1000),
  });
  notifyDashboard({
    userId: identity.userId,
    type: 'TOKEN_REUSE',
    severity: 'CRITICAL',
    description: `Rotated token reused ${Math.round(ageMs / 1000)}s after rotation: possible token theft, identity destroyed: ${t.identityId} [${identity.paranoiaLevel}]`,
    blocked: true,
    ipAddress: context.ip,
    metadata: { ageSeconds: Math.round(ageMs / 1000), userAgent: context.userAgent },
  });
  return 'revoked';
}
