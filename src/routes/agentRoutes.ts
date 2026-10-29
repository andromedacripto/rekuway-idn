import { Request, Response, Router } from 'express';
import { requireAgentAuth } from '../middleware/agentAuth';
import {
  approveRequest,
  createAccessRequest,
  createApprover,
  denyRequest,
  getGrant,
  getRequest,
  grantSummary,
  revokeGrant,
  type Fail,
} from '../services/agentAccess';
import { approveAction, verifyAccess } from '../services/agentVerify';
import { listAudit } from '../services/agentStore';

/**
 * Modo agente: credenciais curtas, com escopo, aprovadas por um humano.
 * Fluxo: approver -> access-request -> approve (código do celular) -> grant+token
 *        -> verify a cada uso (o servidor do cliente pergunta) -> revoke quando quiser.
 * Respostas: { ok: true, ... } ou { ok: false, error: { code, message } } com HTTP coerente.
 */
const router = Router();
router.use(requireAgentAuth);

const tenantOf = (req: Request) => req.apiKey!.userId as string;
const STATUS: Record<string, number> = {
  invalid_request: 400,
  not_found: 404,
  approver_not_found: 404,
  already_exists: 409,
  not_pending: 409,
  invalid_code: 403,
  locked: 429,
};
const sendFail = (res: Response, f: Fail) =>
  res
    .status(STATUS[f.code] ?? 400)
    .json({ ok: false, error: { code: f.code, message: f.message } });
const handle =
  (fn: (req: Request, res: Response) => Promise<unknown>) =>
  async (req: Request, res: Response) => {
    try {
      await fn(req, res);
    } catch {
      res
        .status(503)
        .json({ ok: false, error: { code: 'unavailable', message: 'try again shortly' } });
    }
  };

router.post(
  '/approvers',
  handle(async (req, res) => {
    const r = await createApprover(tenantOf(req), req.body?.approverId);
    if (!r.ok) return sendFail(res, r);
    res.status(201).json(r);
  })
);

router.post(
  '/access-requests',
  handle(async (req, res) => {
    const r = await createAccessRequest(tenantOf(req), req.body ?? {});
    if (!r.ok) return sendFail(res, r);
    const {
      id,
      status,
      expiresAt,
      agentId,
      approverId,
      scopes,
      sensitiveScopes,
      ttlSeconds,
      maxUses,
    } = r.request;
    res.status(201).json({
      ok: true,
      requestId: id,
      status,
      expiresAt,
      agentId,
      approverId,
      scopes,
      sensitiveScopes,
      ttlSeconds,
      maxUses: maxUses ?? null,
    });
  })
);

router.get(
  '/access-requests/:id',
  handle(async (req, res) => {
    const r = await getRequest(tenantOf(req), req.params.id);
    if (!r)
      return sendFail(res, {
        ok: false,
        code: 'not_found',
        message: 'request not found or expired',
      });
    res.json({
      ok: true,
      requestId: r.id,
      status: r.status,
      grantId: r.grantId ?? null,
      expiresAt: r.expiresAt,
    });
  })
);

router.post(
  '/access-requests/:id/approve',
  handle(async (req, res) => {
    const r = await approveRequest(tenantOf(req), req.params.id, req.body?.code);
    if (!r.ok) return sendFail(res, r);
    // O token aparece aqui uma única vez e não é guardado em claro.
    res.json({ ok: true, token: r.token, grant: grantSummary(r.grant) });
  })
);

router.post(
  '/access-requests/:id/deny',
  handle(async (req, res) => {
    const r = await denyRequest(tenantOf(req), req.params.id);
    if (!r.ok) return sendFail(res, r);
    res.json({ ok: true });
  })
);

router.post(
  '/verify',
  handle(async (req, res) => {
    const r = await verifyAccess(tenantOf(req), req.body ?? {});
    if ('ok' in r) return sendFail(res, r);
    res.json({ ok: true, ...r });
  })
);

router.post(
  '/approvals/:id/approve',
  handle(async (req, res) => {
    const r = await approveAction(tenantOf(req), req.params.id, req.body?.code);
    if (!r.ok) return sendFail(res, r);
    res.json({ ok: true, action: r.action, grantId: r.grantId });
  })
);

router.get(
  '/grants/:id',
  handle(async (req, res) => {
    const g = await getGrant(tenantOf(req), req.params.id);
    if (!g) return sendFail(res, { ok: false, code: 'not_found', message: 'grant not found' });
    res.json({ ok: true, grant: grantSummary(g) });
  })
);

router.get(
  '/grants/:id/audit',
  handle(async (req, res) => {
    const g = await getGrant(tenantOf(req), req.params.id);
    if (!g) return sendFail(res, { ok: false, code: 'not_found', message: 'grant not found' });
    const limit = Number(req.query.limit) || 50;
    res.json({ ok: true, grantId: g.id, entries: await listAudit(tenantOf(req), g.id, limit) });
  })
);

router.post(
  '/grants/:id/revoke',
  handle(async (req, res) => {
    const r = await revokeGrant(tenantOf(req), req.params.id);
    if (!r.ok) return sendFail(res, r);
    res.json({ ok: true });
  })
);

export default router;
