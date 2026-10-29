import { sealToken, openToken } from '../utils/tokenVault';
import { generateTotpSecret, otpauthUri, verifyTotp } from '../utils/totp';
import { isBlocked, recordFailure, redisCounter } from '../utils/failureLimiter';
import { sensitiveWithinGranted, validateScopes } from '../utils/agentScopes';
import { notifyDashboard } from './dashboardEvents';
import {
  AccessRequest,
  Approver,
  Grant,
  ID_RE,
  UUID_RE,
  getJson,
  keys,
  newAgentToken,
  newId,
  putJson,
  secondsUntil,
  sha256,
} from './agentStore';

export const MIN_TTL_S = 60;
export const MAX_TTL_S = 24 * 3600;
export const DEFAULT_TTL_S = 3600;
export const REQUEST_TTL_S = 600;
const CODE_FAILURES_MAX = 5;

export type Fail = { ok: false; code: string; message: string };
const fail = (code: string, message: string): Fail => ({ ok: false, code, message });

// ── Aprovadores (a pessoa que aprova com o celular) ───────────
export async function createApprover(tenant: string, approverId: unknown) {
  if (typeof approverId !== 'string' || !ID_RE.test(approverId)) {
    return fail('invalid_request', 'approverId must match [A-Za-z0-9_.@-]{1,64}');
  }
  if (await getJson<Approver>(keys.approver(tenant, approverId))) {
    return fail('already_exists', 'approver already exists');
  }
  const secret = generateTotpSecret();
  const record: Approver = {
    approverId,
    mfaSecret: sealToken(secret, `approver:${tenant}:${approverId}`),
    createdAt: Date.now(),
  };
  await putJson(keys.approver(tenant, approverId), record);
  // O segredo aparece aqui uma única vez.
  return {
    ok: true as const,
    approverId,
    mfa: { secret, otpauthUri: otpauthUri(approverId, secret) },
  };
}

/** Confere o código TOTP do aprovador (anti-replay, e trava após erros repetidos). */
export async function checkApproverCode(
  tenant: string,
  approverId: string,
  code: unknown
): Promise<{ ok: true } | Fail> {
  const failKey = `agentmfa:${tenant}:${approverId}`;
  if (await isBlocked(failKey, CODE_FAILURES_MAX)) {
    return fail('locked', 'too many invalid codes, try again in a minute');
  }
  const approver = await getJson<Approver>(keys.approver(tenant, approverId));
  const secret = approver
    ? openToken(approver.mfaSecret, `approver:${tenant}:${approverId}`)
    : null;
  const result =
    approver && secret && typeof code === 'string'
      ? verifyTotp(secret, code, Date.now(), { lastCounter: approver.lastCounter })
      : { ok: false as const, counter: undefined };
  if (!result.ok || !approver) {
    await recordFailure(failKey, 60);
    return fail('invalid_code', 'invalid or already used code');
  }
  await putJson(keys.approver(tenant, approverId), { ...approver, lastCounter: result.counter });
  return { ok: true };
}

// ── Pedido de acesso ──────────────────────────────────────────
export interface AccessRequestInput {
  agentId?: unknown;
  approverId?: unknown;
  scopes?: unknown;
  sensitiveScopes?: unknown;
  ttlSeconds?: unknown;
  maxUses?: unknown;
  reason?: unknown;
}

export async function createAccessRequest(tenant: string, input: AccessRequestInput) {
  const { agentId, approverId, scopes } = input;
  if (typeof agentId !== 'string' || !ID_RE.test(agentId)) {
    return fail('invalid_request', 'agentId must match [A-Za-z0-9_.@-]{1,64}');
  }
  if (typeof approverId !== 'string' || !ID_RE.test(approverId)) {
    return fail('invalid_request', 'approverId must match [A-Za-z0-9_.@-]{1,64}');
  }
  const scopeError = validateScopes(scopes);
  if (scopeError) return fail('invalid_request', scopeError);
  const sensitive = input.sensitiveScopes ?? [];
  if (Array.isArray(sensitive) && sensitive.length > 0) {
    const e = validateScopes(sensitive, 'sensitiveScopes');
    if (e) return fail('invalid_request', e);
    if (!sensitiveWithinGranted(scopes as string[], sensitive as string[])) {
      return fail('invalid_request', 'sensitiveScopes must be covered by scopes');
    }
  } else if (!Array.isArray(sensitive)) {
    return fail('invalid_request', 'sensitiveScopes must be an array');
  }
  const ttl = input.ttlSeconds === undefined ? DEFAULT_TTL_S : Number(input.ttlSeconds);
  if (!Number.isInteger(ttl) || ttl < MIN_TTL_S || ttl > MAX_TTL_S) {
    return fail(
      'invalid_request',
      `ttlSeconds must be an integer between ${MIN_TTL_S} and ${MAX_TTL_S}`
    );
  }
  let maxUses: number | undefined;
  if (input.maxUses !== undefined) {
    maxUses = Number(input.maxUses);
    if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 1_000_000) {
      return fail('invalid_request', 'maxUses must be an integer between 1 and 1000000');
    }
  }
  const reason = typeof input.reason === 'string' ? input.reason.slice(0, 200) : undefined;
  if (!(await getJson<Approver>(keys.approver(tenant, approverId)))) {
    return fail('approver_not_found', 'create the approver first');
  }

  const now = Date.now();
  const request: AccessRequest = {
    id: newId(),
    agentId,
    approverId,
    scopes: scopes as string[],
    sensitiveScopes: sensitive as string[],
    ttlSeconds: ttl,
    maxUses,
    reason,
    status: 'pending',
    createdAt: now,
    expiresAt: now + REQUEST_TTL_S * 1000,
  };
  await putJson(keys.request(tenant, request.id), request, REQUEST_TTL_S);
  notifyDashboard({
    userId: tenant,
    type: 'AGENT_ACCESS_REQUESTED',
    severity: 'LOW',
    description: `Agent ${agentId} requested access: ${request.scopes.join(', ')}`,
    blocked: false,
    metadata: { requestId: request.id, approverId },
  });
  return { ok: true as const, request };
}

export async function getRequest(tenant: string, id: string) {
  if (!UUID_RE.test(id)) return null;
  return getJson<AccessRequest>(keys.request(tenant, id));
}

export async function approveRequest(tenant: string, requestId: string, code: unknown) {
  const request = await getRequest(tenant, requestId);
  if (!request) return fail('not_found', 'request not found or expired');
  if (request.status !== 'pending')
    return fail('not_pending', `request is already ${request.status}`);

  const codeCheck = await checkApproverCode(tenant, request.approverId, code);
  if (!codeCheck.ok) return codeCheck;

  // Garante um único grant mesmo com duas aprovações simultâneas.
  const first = await redisCounter.incrWindow(`agentreqok:${requestId}`, REQUEST_TTL_S);
  if (first !== 1) return fail('not_pending', 'request is already being approved');

  const now = Date.now();
  const token = newAgentToken();
  const grant: Grant = {
    id: newId(),
    tenant,
    agentId: request.agentId,
    approverId: request.approverId,
    scopes: request.scopes,
    sensitiveScopes: request.sensitiveScopes,
    maxUses: request.maxUses,
    createdAt: now,
    expiresAt: now + request.ttlSeconds * 1000,
    revoked: false,
  };
  const keep = request.ttlSeconds + 24 * 3600; // o registro sobrevive um dia para consulta e auditoria
  await putJson(keys.grant(tenant, grant.id), grant, keep);
  await putJson(keys.token(sha256(token)), { tenant, grantId: grant.id }, request.ttlSeconds + 60);
  await putJson(
    keys.request(tenant, requestId),
    { ...request, status: 'approved', grantId: grant.id },
    secondsUntil(request.expiresAt, now)
  );
  notifyDashboard({
    userId: tenant,
    type: 'AGENT_ACCESS_APPROVED',
    severity: 'LOW',
    description: `Access approved for agent ${grant.agentId} by ${grant.approverId}`,
    blocked: false,
    metadata: { grantId: grant.id, scopes: grant.scopes, expiresAt: grant.expiresAt },
  });
  return { ok: true as const, grant, token };
}

export async function denyRequest(tenant: string, requestId: string) {
  const request = await getRequest(tenant, requestId);
  if (!request) return fail('not_found', 'request not found or expired');
  if (request.status !== 'pending')
    return fail('not_pending', `request is already ${request.status}`);
  await putJson(
    keys.request(tenant, requestId),
    { ...request, status: 'denied' },
    secondsUntil(request.expiresAt)
  );
  return { ok: true as const };
}

// ── Grants ────────────────────────────────────────────────────
export async function getGrant(tenant: string, id: string) {
  if (!UUID_RE.test(id)) return null;
  return getJson<Grant>(keys.grant(tenant, id));
}

export async function revokeGrant(tenant: string, id: string) {
  const grant = await getGrant(tenant, id);
  if (!grant) return fail('not_found', 'grant not found');
  if (!grant.revoked) {
    await putJson(
      keys.grant(tenant, id),
      { ...grant, revoked: true, revokedAt: Date.now() },
      secondsUntil(grant.expiresAt) + 24 * 3600
    );
    notifyDashboard({
      userId: tenant,
      type: 'AGENT_GRANT_REVOKED',
      severity: 'MEDIUM',
      description: `Grant revoked for agent ${grant.agentId}`,
      blocked: true,
      metadata: { grantId: id },
    });
  }
  return { ok: true as const };
}

/** Visão pública do grant: nunca inclui token nem hash. */
export function grantSummary(g: Grant, now = Date.now()) {
  return {
    id: g.id,
    agentId: g.agentId,
    approverId: g.approverId,
    scopes: g.scopes,
    sensitiveScopes: g.sensitiveScopes,
    maxUses: g.maxUses ?? null,
    createdAt: g.createdAt,
    expiresAt: g.expiresAt,
    status: g.revoked ? 'revoked' : now >= g.expiresAt ? 'expired' : 'active',
  };
}
