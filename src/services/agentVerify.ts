import { redisCounter } from '../utils/failureLimiter';
import { isAction, patternCovers, scopeAllows } from '../utils/agentScopes';
import { checkApproverCode, getGrant, type Fail } from './agentAccess';
import { notifyDashboard } from './dashboardEvents';
import {
  Approval,
  Grant,
  UUID_RE,
  audit,
  getJson,
  keys,
  newId,
  putJson,
  secondsUntil,
  sha256,
} from './agentStore';

export const APPROVAL_TTL_S = 300;
const PER_MINUTE = Math.max(1, Number(process.env.AGENT_RATE_PER_MINUTE) || 120);

export type DenyReason =
  | 'invalid_token'
  | 'expired'
  | 'revoked'
  | 'scope_denied'
  | 'rate_limited'
  | 'limit_reached'
  | 'approval_required'
  | 'approval_pending'
  | 'approval_invalid'
  | 'unavailable';

export type VerifyResult =
  | {
      allowed: true;
      grantId: string;
      agentId: string;
      remainingUses: number | null;
      expiresAt: number;
    }
  | { allowed: false; reason: DenyReason; approvalId?: string; approvalExpiresAt?: number };

const deny = (
  reason: DenyReason,
  extra: { approvalId?: string; approvalExpiresAt?: number } = {}
) => ({ allowed: false, reason, ...extra }) as const;

/**
 * Verifica se o agente (dono do token) pode executar `action` agora.
 * Chamada pelo servidor do cliente a cada uso. O token é estável (não troca a
 * cada uso), então várias chamadas em paralelo funcionam.
 */
export async function verifyAccess(
  tenant: string,
  input: { token: unknown; action: unknown; approvalId?: unknown }
): Promise<VerifyResult | Fail> {
  const { token, action, approvalId } = input;
  if (typeof token !== 'string' || !token.startsWith('agt_') || token.length > 100) {
    return deny('invalid_token');
  }
  if (!isAction(action)) {
    return {
      ok: false,
      code: 'invalid_request',
      message: 'action must be a concrete scope like db:read',
    };
  }

  const entry = await getJson<{ tenant: string; grantId: string }>(keys.token(sha256(token)));
  // Token de outro cliente se comporta como inexistente.
  if (!entry || entry.tenant !== tenant) return deny('invalid_token');
  const grant = await getGrant(tenant, entry.grantId);
  if (!grant) return deny('invalid_token');

  const now = Date.now();
  const refuse = async (r: VerifyResult & { allowed: false }) => {
    await audit(tenant, grant.id, { action, result: 'denied', reason: r.reason });
    return r;
  };

  if (grant.revoked) return refuse(deny('revoked'));
  if (now >= grant.expiresAt) return refuse(deny('expired'));
  if (!scopeAllows(grant.scopes, action)) return refuse(deny('scope_denied'));

  const sensitive = grant.sensitiveScopes.some((p) => patternCovers(p, action));
  let approval: Approval | null = null;
  if (sensitive) {
    if (approvalId === undefined) {
      const created = await requestApproval(tenant, grant, action);
      return refuse(deny('approval_required', created));
    }
    if (typeof approvalId !== 'string' || !UUID_RE.test(approvalId)) {
      return refuse(deny('approval_invalid'));
    }
    approval = await getJson<Approval>(keys.approval(tenant, approvalId));
    if (
      !approval ||
      approval.grantId !== grant.id ||
      approval.action !== action ||
      now >= approval.expiresAt
    ) {
      return refuse(deny('approval_invalid'));
    }
    if (approval.status === 'pending') {
      return refuse(
        deny('approval_pending', { approvalId, approvalExpiresAt: approval.expiresAt })
      );
    }
  }

  // Limites (contadores atômicos). Falha do Redis nega: fail-closed.
  try {
    if ((await redisCounter.incrWindow(`agentrl:${grant.id}`, 60)) > PER_MINUTE) {
      return refuse(deny('rate_limited'));
    }
    let used = 0;
    if (grant.maxUses) {
      used = await redisCounter.incrWindow(
        `agentuse:${grant.id}`,
        secondsUntil(grant.expiresAt, now)
      );
      if (used > grant.maxUses) return refuse(deny('limit_reached'));
    }
    // A aprovação vale uma única vez.
    if (approval) {
      const first = await redisCounter.incrWindow(`agentappr:${approval.id}`, APPROVAL_TTL_S + 60);
      if (first !== 1) return refuse(deny('approval_invalid'));
    }
    await audit(tenant, grant.id, { action, result: 'allowed' });
    return {
      allowed: true,
      grantId: grant.id,
      agentId: grant.agentId,
      remainingUses: grant.maxUses ? Math.max(0, grant.maxUses - used) : null,
      expiresAt: grant.expiresAt,
    };
  } catch {
    return deny('unavailable');
  }
}

/** Cria (ou reaproveita) o pedido de aprovação humana para uma ação sensível. */
async function requestApproval(tenant: string, grant: Grant, action: string) {
  const ptrKey = keys.approvalPtr(tenant, grant.id, action);
  const existing = await getJson<{ id: string }>(ptrKey);
  if (existing) {
    const a = await getJson<Approval>(keys.approval(tenant, existing.id));
    if (a && a.status === 'pending') return { approvalId: a.id, approvalExpiresAt: a.expiresAt };
  }
  const now = Date.now();
  const approval: Approval = {
    id: newId(),
    grantId: grant.id,
    action,
    status: 'pending',
    createdAt: now,
    expiresAt: now + APPROVAL_TTL_S * 1000,
  };
  await putJson(keys.approval(tenant, approval.id), approval, APPROVAL_TTL_S);
  await putJson(ptrKey, { id: approval.id }, APPROVAL_TTL_S);
  notifyDashboard({
    userId: tenant,
    type: 'AGENT_APPROVAL_REQUESTED',
    severity: 'MEDIUM',
    description: `Agent ${grant.agentId} needs human approval for ${action}`,
    blocked: false,
    metadata: { approvalId: approval.id, grantId: grant.id, approverId: grant.approverId },
  });
  return { approvalId: approval.id, approvalExpiresAt: approval.expiresAt };
}

/** O aprovador confirma a ação sensível com o código do celular. */
export async function approveAction(tenant: string, approvalId: string, code: unknown) {
  if (!UUID_RE.test(approvalId))
    return { ok: false as const, code: 'not_found', message: 'approval not found' };
  const approval = await getJson<Approval>(keys.approval(tenant, approvalId));
  if (!approval || Date.now() >= approval.expiresAt) {
    return { ok: false as const, code: 'not_found', message: 'approval not found or expired' };
  }
  if (approval.status !== 'pending') {
    return { ok: false as const, code: 'not_pending', message: 'approval already decided' };
  }
  const grant = await getGrant(tenant, approval.grantId);
  if (!grant || grant.revoked) {
    return { ok: false as const, code: 'not_found', message: 'grant not found or revoked' };
  }
  const check = await checkApproverCode(tenant, grant.approverId, code);
  if (!check.ok) {
    if (check.code === 'locked') {
      notifyDashboard({
        userId: tenant,
        type: 'AGENT_APPROVAL_FAILED',
        severity: 'HIGH',
        description: `Repeated invalid approval codes for approver ${grant.approverId}`,
        blocked: true,
        metadata: { approvalId },
      });
    }
    return check;
  }
  await putJson(
    keys.approval(tenant, approvalId),
    { ...approval, status: 'approved' },
    secondsUntil(approval.expiresAt)
  );
  notifyDashboard({
    userId: tenant,
    type: 'AGENT_SENSITIVE_APPROVED',
    severity: 'LOW',
    description: `Sensitive action ${approval.action} approved for agent ${grant.agentId}`,
    blocked: false,
    metadata: { approvalId, grantId: grant.id },
  });
  return { ok: true as const, action: approval.action, grantId: grant.id };
}
