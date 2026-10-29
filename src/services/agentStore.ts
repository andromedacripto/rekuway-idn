import crypto from 'crypto';
import { db } from '../config/database';

/**
 * Armazenamento do modo agente. Tudo é isolado por `tenant` (a conta Rekuway do
 * cliente, que é o userId da chave de API): um cliente nunca enxerga o outro.
 * O token do agente NUNCA é guardado: só o SHA-256 dele, no índice `agenttok:`.
 */
export interface Approver {
  approverId: string;
  /** Segredo TOTP cifrado (tokenVault). */
  mfaSecret: string;
  lastCounter?: number;
  createdAt: number;
}

export interface AccessRequest {
  id: string;
  agentId: string;
  approverId: string;
  scopes: string[];
  sensitiveScopes: string[];
  ttlSeconds: number;
  maxUses?: number;
  reason?: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: number;
  expiresAt: number;
  grantId?: string;
}

export interface Grant {
  id: string;
  tenant: string;
  agentId: string;
  approverId: string;
  scopes: string[];
  sensitiveScopes: string[];
  maxUses?: number;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
  revokedAt?: number;
}

export interface Approval {
  id: string;
  grantId: string;
  action: string;
  status: 'pending' | 'approved';
  createdAt: number;
  expiresAt: number;
}

export const keys = {
  approver: (t: string, a: string) => `agent:${t}:approver:${a}`,
  request: (t: string, id: string) => `agent:${t}:req:${id}`,
  grant: (t: string, id: string) => `agent:${t}:grant:${id}`,
  approval: (t: string, id: string) => `agent:${t}:appr:${id}`,
  approvalPtr: (t: string, grantId: string, action: string) =>
    `agent:${t}:apprptr:${grantId}:${action}`,
  audit: (t: string, grantId: string) => `agent:${t}:audit:${grantId}:`,
  token: (hash: string) => `agenttok:${hash}`,
};

export const sha256 = (v: string) => crypto.createHash('sha256').update(v, 'utf8').digest('hex');
export const newId = () => crypto.randomUUID();
export const newAgentToken = () => `agt_${crypto.randomBytes(32).toString('hex')}`;
export const ID_RE = /^[A-Za-z0-9_.@-]{1,64}$/;
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const getJson = async <T>(key: string) => (await db.get(key)) as T | null;
export const putJson = (key: string, value: unknown, ttlSeconds?: number) =>
  db.set(key, value, ttlSeconds);

export const secondsUntil = (ts: number, now = Date.now()) =>
  Math.max(1, Math.ceil((ts - now) / 1000));

// ── Trilha de auditoria ───────────────────────────────────────
// Uma chave por evento (não uma lista): chamadas paralelas não perdem registros.
const AUDIT_TTL_S = 30 * 24 * 3600;

export interface AuditEntry {
  at: number;
  action: string;
  result: 'allowed' | 'denied';
  reason?: string;
}

export async function audit(tenant: string, grantId: string, entry: Omit<AuditEntry, 'at'>) {
  const at = Date.now();
  const key = `${keys.audit(tenant, grantId)}${String(at).padStart(14, '0')}-${crypto.randomBytes(3).toString('hex')}`;
  await db.set(key, { at, ...entry }, AUDIT_TTL_S);
}

export async function listAudit(
  tenant: string,
  grantId: string,
  limit = 50
): Promise<AuditEntry[]> {
  const found = await db.keys(`${keys.audit(tenant, grantId)}*`);
  const newest = found.sort().slice(-Math.min(Math.max(limit, 1), 200));
  const rows = await Promise.all(newest.map((k) => getJson<AuditEntry>(k)));
  return rows.filter((r): r is AuditEntry => !!r).sort((a, b) => b.at - a.at);
}
