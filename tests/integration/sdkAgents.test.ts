import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

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

import type { AddressInfo } from 'net';
import express from 'express';
import app from '../../src/app';
import { totpAt } from '../../src/utils/totp';
import { Rekuway, RekuwayError, agentGuard } from '../../sdk/rekuway';

let baseUrl = '';
let server: ReturnType<typeof app.listen>;
let n = 0;
const nextIp = () => `198.19.0.${++n}`;
const SECRET = 'test-internal-secret-0123456789';

async function apiKey(userId: string): Promise<string> {
  const res = await fetch(`${baseUrl}/api-keys`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-internal-secret': SECRET,
      'x-real-ip': nextIp(),
    },
    body: JSON.stringify({ userId, name: 'agents-sdk', tier: 'enterprise' }),
  });
  return (await res.json()).apiKey.key as string;
}

beforeAll(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  server.close();
});

describe('SDK: modo agente de ponta a ponta', () => {
  it('pedido, aprovação por MFA, uso com escopo, ação sensível e revogação', async () => {
    const rk = new Rekuway({
      baseUrl,
      apiKey: await apiKey('sdk-agents'),
      headers: { 'x-real-ip': nextIp() },
    });
    const { mfa } = await rk.agents.createApprover('maria');
    const code = (step: number) => totpAt(mfa.secret, Date.now() + step * 30_000);

    const { requestId } = await rk.agents.requestAccess({
      agentId: 'assistente-financeiro',
      approverId: 'maria',
      scopes: ['db:read', 'db:write'],
      sensitiveScopes: ['db:write'],
      ttlSeconds: 600,
      reason: 'fechamento do mês',
    });
    expect((await rk.agents.getRequest(requestId)).status).toBe('pending');

    await expect(rk.agents.approve(requestId, '000000')).rejects.toMatchObject({
      code: 'invalid_code',
    });
    const { token, grant } = await rk.agents.approve(requestId, code(-1));
    expect(grant.status).toBe('active');

    // Servidor do cliente protegido com o middleware do SDK.
    const web = express();
    web.get('/orders', agentGuard(rk, 'db:read'), (_req, res) => res.json({ orders: [1, 2, 3] }));
    web.post('/orders', agentGuard(rk, 'db:write'), (_req, res) => res.json({ created: true }));
    const srv = web.listen(0);
    await new Promise((r) => srv.once('listening', r));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const as = (headers: Record<string, string> = {}) => ({
      Authorization: `Bearer ${token}`,
      ...headers,
    });

    try {
      expect((await fetch(`${url}/orders`)).status).toBe(401);
      expect((await fetch(`${url}/orders`, { headers: as() })).status).toBe(200);

      // ação sensível: o agente é parado e recebe o id da aprovação
      const blocked = await fetch(`${url}/orders`, { method: 'POST', headers: as() });
      expect(blocked.status).toBe(202);
      const { approvalId } = await blocked.json();
      expect(approvalId).toBeDefined();

      // o humano aprova no celular; o agente repete com o id
      await rk.agents.approveAction(approvalId, code(0));
      const done = await fetch(`${url}/orders`, {
        method: 'POST',
        headers: as({ 'x-approval-id': approvalId }),
      });
      expect(done.status).toBe(200);
      // a aprovação vale uma vez
      const again = await fetch(`${url}/orders`, {
        method: 'POST',
        headers: as({ 'x-approval-id': approvalId }),
      });
      expect(again.status).toBe(403);

      // paralelismo: token estável
      const many = await Promise.all(
        Array.from({ length: 8 }, () => fetch(`${url}/orders`, { headers: as() }))
      );
      expect(many.every((r) => r.status === 200)).toBe(true);

      // botão de pânico
      await rk.agents.revoke(grant.id);
      expect((await fetch(`${url}/orders`, { headers: as() })).status).toBe(403);
      expect((await rk.agents.verify(token, 'db:read')).allowed).toBe(false);
    } finally {
      srv.close();
    }

    const trail = await rk.agents.audit(grant.id);
    expect(trail.some((e) => e.result === 'allowed')).toBe(true);
    expect(trail[0]).toMatchObject({ result: 'denied', reason: 'revoked' });
    expect((await rk.agents.getGrant(grant.id)).status).toBe('revoked');
  }, 20000);

  it('erros de uso viram RekuwayError com código; sem chave, erro claro', async () => {
    const rk = new Rekuway({
      baseUrl,
      apiKey: await apiKey('sdk-agents-2'),
      headers: { 'x-real-ip': nextIp() },
    });
    await expect(
      rk.agents.requestAccess({ agentId: 'a', approverId: 'nao-existe', scopes: ['db:read'] })
    ).rejects.toMatchObject({ code: 'approver_not_found', httpStatus: 404 });
    await expect(
      rk.agents.requestAccess({ agentId: 'a', approverId: 'x', scopes: ['*'] })
    ).rejects.toBeInstanceOf(RekuwayError);
    const noKey = new Rekuway({ baseUrl });
    await expect(noKey.agents.createApprover('x')).rejects.toThrow(/apiKey is required/);
    const wrongKey = new Rekuway({
      baseUrl,
      apiKey: 'rkwy_live_invalida',
      headers: { 'x-real-ip': nextIp() },
    });
    await expect(wrongKey.agents.createApprover('x')).rejects.toMatchObject({
      code: 'unauthorized',
    });
  });
});
