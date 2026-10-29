import { beforeAll, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

const h = vi.hoisted(() => {
  process.env.INTERNAL_SECRET = 'test-internal-secret-0123456789';
  process.env.CRON_SECRET = 'test-cron-secret-0123456789';
  process.env.ALLOWED_ORIGINS = 'https://app.rekuway.test';
  delete process.env.AI_SERVICE_URL;
  delete process.env.AI_SERVICE_TOKEN;
  return {
    store: new Map<string, unknown>(),
    counters: new Map<string, number>(),
    redisDown: { value: false },
  };
});

// ── Redis falso (contadores do rate limit) ──
vi.mock('../../src/config/redis', () => ({
  redis: {
    multi: () => {
      let key = '';
      const chain = {
        incr(k: string) {
          key = k;
          return chain;
        },
        expire() {
          return chain;
        },
        async exec() {
          if (h.redisDown.value) throw new Error('redis down');
          const n = (h.counters.get(key) ?? 0) + 1;
          h.counters.set(key, n);
          return [n, 1];
        },
      };
      return chain;
    },
    get: async (k: string) => {
      if (h.redisDown.value) throw new Error('redis down');
      return h.counters.get(k) ?? null;
    },
  },
}));

// ── Banco em memória ──
vi.mock('../../src/config/database', () => {
  const copy = <T>(v: T): T => (v === undefined ? v : JSON.parse(JSON.stringify(v)));
  const byPrefix = (p: string) =>
    [...h.store.entries()].filter(([k]) => k.startsWith(p)).map(([, v]) => copy(v));
  return {
    db: {
      set: async (k: string, v: unknown) => (h.store.set(k, copy(v)), true),
      get: async (k: string) => {
        const v = h.store.get(k);
        return v === undefined || v === '' ? null : copy(v);
      },
      delete: async (k: string) => h.store.delete(k),
      keys: async (p: string) =>
        [...h.store.keys()].filter((k) => k.startsWith(p.replace('*', ''))),
      setIdentity: async (id: string, v: unknown) => void h.store.set(`identity:${id}`, copy(v)),
      getIdentity: async (id: string) => copy(h.store.get(`identity:${id}`) ?? null),
      deleteIdentity: async (id: string) => h.store.delete(`identity:${id}`),
      listIdentities: async () => byPrefix('identity:'),
      setApiKey: async (k: string, v: unknown) => void h.store.set(`apikey:${k}`, copy(v)),
      getApiKey: async (k: string) => copy(h.store.get(`apikey:${k}`) ?? null),
      listApiKeys: async () => byPrefix('apikey:'),
      cleanExpired: async () => 0,
    },
  };
});

import app from '../../src/app';
import { sha256 } from '../../src/services/agentStore';
import { totpAt } from '../../src/utils/totp';

const SECRET = { 'x-internal-secret': 'test-internal-secret-0123456789' };
let n = 0;
const ip = () => `198.18.0.${++n}`;

async function newKey(userId: string): Promise<string> {
  const res = await request(app)
    .post('/api-keys')
    .set(SECRET)
    .set('x-real-ip', ip())
    .send({ userId, name: 'agents', tier: 'enterprise' });
  return res.body.apiKey.key as string;
}

const api = (key: string) => ({
  post: (path: string, body: unknown = {}) =>
    request(app)
      .post(`/agents${path}`)
      .set('Authorization', `Bearer ${key}`)
      .set('x-real-ip', ip())
      .send(body as object),
  get: (path: string) =>
    request(app).get(`/agents${path}`).set('Authorization', `Bearer ${key}`).set('x-real-ip', ip()),
});

/** Cria aprovador novo. `code(k)` gera o código do passo atual + k (cada passo só vale uma vez). */
async function setup(userId: string, opts: Record<string, unknown> = {}) {
  const key = await newKey(userId);
  const a = api(key);
  const approverId = `approver-${++n}`;
  const created = await a.post('/approvers', { approverId });
  const secret = created.body.mfa.secret as string;
  const code = (step = 0) => totpAt(secret, Date.now() + step * 30_000);
  const reqRes = await a.post('/access-requests', {
    agentId: 'agent-1',
    approverId,
    scopes: ['db:read'],
    ...opts,
  });
  return { key, a, approverId, secret, code, requestId: reqRes.body.requestId as string, reqRes };
}

async function granted(userId: string, opts: Record<string, unknown> = {}) {
  const s = await setup(userId, opts);
  // passo -1 primeiro: assim 0 e +1 continuam disponíveis para aprovações seguintes
  const ok = await s.a.post(`/access-requests/${s.requestId}/approve`, { code: s.code(-1) });
  return { ...s, token: ok.body.token as string, grantId: ok.body.grant.id as string, ok };
}

beforeAll(() => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
});

describe('/agents: autenticação', () => {
  it('chave ausente ou inválida recebe 401 explícito', async () => {
    const none = await request(app).post('/agents/approvers').set('x-real-ip', ip()).send({});
    expect(none.status).toBe(401);
    expect(none.body.error.code).toBe('unauthorized');
    const bad = await api('rkwy_live_invalida').post('/approvers', { approverId: 'x' });
    expect(bad.status).toBe(401);
  });

  it('bloqueia o IP depois de muitas falhas de autenticação', async () => {
    const same = ip();
    for (let i = 0; i < 20; i++) {
      await request(app)
        .post('/agents/approvers')
        .set('x-real-ip', same)
        .set('Authorization', 'Bearer rkwy_live_x')
        .send({});
    }
    const res = await request(app).post('/agents/approvers').set('x-real-ip', same).send({});
    expect(res.status).toBe(429);
  });
});

describe('/agents: aprovador e pedido', () => {
  it('cria aprovador com MFA (segredo cifrado) e recusa duplicado', async () => {
    const key = await newKey('tenant-a');
    const a = api(key);
    const r = await a.post('/approvers', { approverId: 'maria' });
    expect(r.status).toBe(201);
    expect(r.body.mfa.secret).toMatch(/^[A-Z2-7]{32}$/);
    const stored = h.store.get('agent:tenant-a:approver:maria') as { mfaSecret: string };
    expect(stored.mfaSecret.startsWith('v1:')).toBe(true);
    expect(JSON.stringify(stored)).not.toContain(r.body.mfa.secret);
    expect((await a.post('/approvers', { approverId: 'maria' })).status).toBe(409);
    expect((await a.post('/approvers', { approverId: 'a b' })).status).toBe(400);
  });

  it('valida o pedido', async () => {
    const { a, approverId } = await setup('tenant-b');
    const base = { agentId: 'g', approverId, scopes: ['db:read'] };
    const cases: Array<[Record<string, unknown>, number]> = [
      [{ ...base, scopes: ['*'] }, 400],
      [{ ...base, scopes: [] }, 400],
      [{ ...base, sensitiveScopes: ['db:write'] }, 400],
      [{ ...base, ttlSeconds: 5 }, 400],
      [{ ...base, ttlSeconds: 999999 }, 400],
      [{ ...base, maxUses: 0 }, 400],
      [{ ...base, approverId: 'ninguem' }, 404],
      [{ ...base, agentId: '' }, 400],
      [base, 201],
    ];
    for (const [body, status] of cases) {
      expect((await a.post('/access-requests', body)).status).toBe(status);
    }
  });
});

describe('/agents: aprovação e token', () => {
  it('código errado recusa; certo emite o token uma vez, sem guardá-lo em claro', async () => {
    const s = await setup('tenant-c');
    const wrong = await s.a.post(`/access-requests/${s.requestId}/approve`, { code: '000000' });
    expect(wrong.status).toBe(403);
    expect(wrong.body.error.code).toBe('invalid_code');

    const ok = await s.a.post(`/access-requests/${s.requestId}/approve`, { code: s.code(-1) });
    expect(ok.status).toBe(200);
    expect(ok.body.token).toMatch(/^agt_[0-9a-f]{64}$/);
    expect(ok.body.grant.status).toBe('active');
    expect(JSON.stringify(Object.fromEntries(h.store))).not.toContain(ok.body.token);
    expect(h.store.get(`agenttok:${sha256(ok.body.token)}`)).toBeDefined();

    expect(
      (await s.a.post(`/access-requests/${s.requestId}/approve`, { code: s.code(0) })).status
    ).toBe(409);
    expect((await s.a.get(`/access-requests/${s.requestId}`)).body.status).toBe('approved');
  });

  it('o mesmo código não vale duas vezes (anti-replay)', async () => {
    const s = await setup('tenant-d');
    const second = await s.a.post('/access-requests', {
      agentId: 'g2',
      approverId: s.approverId,
      scopes: ['db:read'],
    });
    const code = s.code(0);
    expect((await s.a.post(`/access-requests/${s.requestId}/approve`, { code })).status).toBe(200);
    expect(
      (await s.a.post(`/access-requests/${second.body.requestId}/approve`, { code })).status
    ).toBe(403);
  });

  it('travam depois de 5 códigos errados, mesmo que o próximo seja o certo', async () => {
    const s = await setup('tenant-e');
    for (let i = 0; i < 5; i++) {
      await s.a.post(`/access-requests/${s.requestId}/approve`, { code: '111111' });
    }
    const res = await s.a.post(`/access-requests/${s.requestId}/approve`, { code: s.code(0) });
    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe('locked');
  });

  it('pedido negado não pode ser aprovado depois', async () => {
    const s = await setup('tenant-f');
    expect((await s.a.post(`/access-requests/${s.requestId}/deny`)).status).toBe(200);
    expect(
      (await s.a.post(`/access-requests/${s.requestId}/approve`, { code: s.code(0) })).status
    ).toBe(409);
  });
});

describe('/agents: verify', () => {
  it('permite o escopo concedido, nega o resto e o token inventado', async () => {
    const g = await granted('tenant-g', { scopes: ['db:read', 'files:*'] });
    const ok = await g.a.post('/verify', { token: g.token, action: 'db:read' });
    expect(ok.body).toMatchObject({
      ok: true,
      allowed: true,
      agentId: 'agent-1',
      remainingUses: null,
    });
    expect(
      (await g.a.post('/verify', { token: g.token, action: 'files:upload' })).body.allowed
    ).toBe(true);
    expect((await g.a.post('/verify', { token: g.token, action: 'db:write' })).body).toMatchObject({
      allowed: false,
      reason: 'scope_denied',
    });
    expect(
      (await g.a.post('/verify', { token: 'agt_' + '0'.repeat(64), action: 'db:read' })).body.reason
    ).toBe('invalid_token');
    expect((await g.a.post('/verify', { token: g.token, action: 'db:*' })).status).toBe(400);
  });

  it('o token é estável: 15 chamadas em paralelo passam (sem troca de token)', async () => {
    const g = await granted('tenant-h');
    const results = await Promise.all(
      Array.from({ length: 15 }, () => g.a.post('/verify', { token: g.token, action: 'db:read' }))
    );
    expect(results.every((r) => r.body.allowed === true)).toBe(true);
  });

  it('respeita o limite de usos e informa o que resta', async () => {
    const g = await granted('tenant-i', { maxUses: 3 });
    const seen: unknown[] = [];
    for (let i = 0; i < 4; i++) {
      const r = await g.a.post('/verify', { token: g.token, action: 'db:read' });
      seen.push(r.body.allowed ? r.body.remainingUses : r.body.reason);
    }
    expect(seen).toEqual([2, 1, 0, 'limit_reached']);
  });

  it('expira no prazo', async () => {
    const g = await granted('tenant-j');
    (h.store.get(`agent:tenant-j:grant:${g.grantId}`) as { expiresAt: number }).expiresAt =
      Date.now() - 1;
    expect((await g.a.post('/verify', { token: g.token, action: 'db:read' })).body.reason).toBe(
      'expired'
    );
  });

  it('revogar corta o acesso na hora e fica na auditoria', async () => {
    const g = await granted('tenant-k');
    expect((await g.a.post('/verify', { token: g.token, action: 'db:read' })).body.allowed).toBe(
      true
    );
    expect((await g.a.post(`/grants/${g.grantId}/revoke`)).status).toBe(200);
    expect((await g.a.post('/verify', { token: g.token, action: 'db:read' })).body.reason).toBe(
      'revoked'
    );
    expect((await g.a.get(`/grants/${g.grantId}`)).body.grant.status).toBe('revoked');
    const entries = (await g.a.get(`/grants/${g.grantId}/audit`)).body.entries as Array<{
      result: string;
      reason?: string;
    }>;
    expect(entries.map((e) => e.result)).toEqual(['denied', 'allowed']);
    expect(entries[0].reason).toBe('revoked');
  });

  it('um cliente não enxerga o grant do outro', async () => {
    const g = await granted('tenant-l');
    const otherKey = await newKey('tenant-m');
    const other = api(otherKey);
    expect((await other.post('/verify', { token: g.token, action: 'db:read' })).body.reason).toBe(
      'invalid_token'
    );
    expect((await other.get(`/grants/${g.grantId}`)).status).toBe(404);
    expect((await other.post(`/grants/${g.grantId}/revoke`)).status).toBe(404);
    expect((await other.get(`/access-requests/${g.requestId}`)).status).toBe(404);
  });
});

describe('/agents: ação sensível exige aprovação humana', () => {
  const sensitive = { scopes: ['db:read', 'db:write'], sensitiveScopes: ['db:write'] };

  it('pede, aguarda, aprova com o código e libera uma única vez', async () => {
    const g = await granted('tenant-n', sensitive);
    expect((await g.a.post('/verify', { token: g.token, action: 'db:read' })).body.allowed).toBe(
      true
    );

    const first = await g.a.post('/verify', { token: g.token, action: 'db:write' });
    expect(first.body).toMatchObject({ allowed: false, reason: 'approval_required' });
    const approvalId = first.body.approvalId as string;
    const again = await g.a.post('/verify', { token: g.token, action: 'db:write' });
    expect(again.body.approvalId).toBe(approvalId); // reaproveita o pedido pendente

    const pending = await g.a.post('/verify', { token: g.token, action: 'db:write', approvalId });
    expect(pending.body.reason).toBe('approval_pending');

    expect((await g.a.post(`/approvals/${approvalId}/approve`, { code: '000000' })).status).toBe(
      403
    );
    const approved = await g.a.post(`/approvals/${approvalId}/approve`, { code: g.code(0) });
    expect(approved.status).toBe(200);

    const go = await g.a.post('/verify', { token: g.token, action: 'db:write', approvalId });
    expect(go.body.allowed).toBe(true);
    const reuse = await g.a.post('/verify', { token: g.token, action: 'db:write', approvalId });
    expect(reuse.body).toMatchObject({ allowed: false, reason: 'approval_invalid' });
  });

  it('a aprovação não vale para outra ação nem para outro grant', async () => {
    const g = await granted('tenant-o', {
      scopes: ['db:*'],
      sensitiveScopes: ['db:write', 'db:delete'],
    });
    const w = await g.a.post('/verify', { token: g.token, action: 'db:write' });
    await g.a.post(`/approvals/${w.body.approvalId}/approve`, { code: g.code(0) });
    const wrongAction = await g.a.post('/verify', {
      token: g.token,
      action: 'db:delete',
      approvalId: w.body.approvalId,
    });
    expect(wrongAction.body.reason).toBe('approval_invalid');
    const wrongFormat = await g.a.post('/verify', {
      token: g.token,
      action: 'db:write',
      approvalId: 'x',
    });
    expect(wrongFormat.body.reason).toBe('approval_invalid');
  });

  it('o aprovador de outro cliente não consegue aprovar', async () => {
    const g = await granted('tenant-p', sensitive);
    const w = await g.a.post('/verify', { token: g.token, action: 'db:write' });
    const other = api(await newKey('tenant-q'));
    expect(
      (await other.post(`/approvals/${w.body.approvalId}/approve`, { code: g.code(0) })).status
    ).toBe(404);
  });
});

describe('/agents: Redis fora do ar', () => {
  it('verify nega (fail-closed) em vez de liberar', async () => {
    const g = await granted('tenant-r');
    h.redisDown.value = true;
    try {
      const r = await g.a.post('/verify', { token: g.token, action: 'db:read' });
      expect(r.status).not.toBe(200);
    } finally {
      h.redisDown.value = false;
    }
  });
});
