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

const SECRET = { 'x-internal-secret': 'test-internal-secret-0123456789' };
let n = 0;
const ip = () => `192.0.2.${++n}`;

async function newKey(tier: string, userId = `tenant-${++n}`): Promise<string> {
  const res = await request(app)
    .post('/api-keys')
    .set(SECRET)
    .set('x-real-ip', ip())
    .send({ userId, name: 'server', tier });
  return res.body.apiKey.key as string;
}

async function newToken(key: string, connIp: string, level: string): Promise<string> {
  const res = await request(app)
    .post('/identity/new')
    .set('Authorization', `Bearer ${key}`)
    .set('x-real-ip', connIp)
    .send({ paranoiaLevel: level });
  return res.body.token as string;
}

/** Uma chamada /identity/check feita pelo SERVIDOR do cliente. */
function serverCheck(
  key: string | undefined,
  connIp: string,
  token: string,
  ctx: { ip?: string; ua?: string } = {}
) {
  let r = request(app).post('/identity/check').set('x-real-ip', connIp);
  if (key) r = r.set('Authorization', `Bearer ${key}`);
  if (ctx.ip) r = r.set('x-end-user-ip', ctx.ip);
  if (ctx.ua) r = r.set('x-end-user-user-agent', ctx.ua);
  return r.send({ token });
}

beforeAll(() => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
});

describe('servidor do cliente chamando em nome dos usuários', () => {
  it('não é limitado a 10 req/min por IP: vale o plano da chave', async () => {
    const key = await newKey('enterprise');
    const serverIp = ip();
    let token = await newToken(key, serverIp, 'low');
    let allowed = 0;
    for (let i = 0; i < 25; i++) {
      const r = await serverCheck(key, serverIp, token);
      if (r.body.action === 'ALLOWED') {
        allowed++;
        token = r.body.token;
      }
    }
    expect(allowed).toBe(25);
  }, 20000);

  it('sem chave, o mesmo IP continua limitado a 10 por minuto', async () => {
    const key = await newKey('enterprise');
    const connIp = ip();
    let token = await newToken(key, ip(), 'low');
    let allowed = 0;
    for (let i = 0; i < 15; i++) {
      const r = await serverCheck(undefined, connIp, token);
      if (r.body.action === 'ALLOWED') {
        allowed++;
        token = r.body.token;
      }
    }
    expect(allowed).toBe(10);
  }, 20000);

  it('o IP do usuário repassado alimenta o risco; sem repassar, o IP é o do servidor', async () => {
    const key = await newKey('enterprise');
    const serverIp = ip();

    // com contexto: IP novo do usuário trava a sessão (nível medium)
    let t = await newToken(key, serverIp, 'medium');
    const a = await serverCheck(key, serverIp, t, { ip: '203.0.113.10', ua: 'UA-A' });
    expect(a.body.action).toBe('ALLOWED');
    const b = await serverCheck(key, serverIp, a.body.token, { ip: '203.0.113.99', ua: 'UA-A' });
    expect(b.body.action).toBe('STEP_UP_REQUIRED');

    // controle: sem repassar contexto, tudo vem do IP do servidor e nada muda
    t = await newToken(key, serverIp, 'medium');
    const c = await serverCheck(key, serverIp, t);
    const d = await serverCheck(key, serverIp, c.body.token);
    expect([c.body.action, d.body.action]).toEqual(['ALLOWED', 'ALLOWED']);
  }, 20000);

  it('cabeçalhos de contexto sem chave válida são ignorados (não dá para forjar)', async () => {
    const key = await newKey('enterprise');
    const connIp = ip();
    const t = await newToken(key, connIp, 'medium');
    const a = await serverCheck(undefined, connIp, t, { ip: '203.0.113.10' });
    const b = await serverCheck(undefined, connIp, a.body.token, { ip: '203.0.113.99' });
    expect([a.body.action, b.body.action]).toEqual(['ALLOWED', 'ALLOWED']);

    const c = await serverCheck('rkwy_live_chave_invalida', connIp, b.body.token, {
      ip: '203.0.113.200',
    });
    expect(c.body.action).toBe('ALLOWED'); // tratado como anônimo, IP forjado ignorado
  }, 20000);

  it('o plano da chave limita o tráfego (hobby: 10 req/min)', async () => {
    const key = await newKey('hobby');
    const serverIp = ip();
    let token = await newToken(key, serverIp, 'low');
    let allowed = 0;
    let last = {} as Record<string, unknown>;
    for (let i = 0; i < 14; i++) {
      const r = await serverCheck(key, serverIp, token);
      last = r.body;
      if (r.body.action === 'ALLOWED') {
        allowed++;
        token = r.body.token;
      }
    }
    expect(allowed).toBeGreaterThan(0);
    expect(allowed).toBeLessThanOrEqual(10);
    expect(last).toEqual({ success: true, status: 'ok', mode: 'stealth' });
  }, 20000);

  it('rotas de credencial: servidor sem IP de usuário pula o limite por IP, mas o limite por identidade vale', async () => {
    const key = await newKey('enterprise');
    const serverIp = ip();
    const id = '33333333-3333-4333-8333-333333333333';
    for (let i = 0; i < 8; i++) {
      const r = await request(app)
        .post('/identity/heartbeat')
        .set('Authorization', `Bearer ${key}`)
        .set('x-real-ip', serverIp)
        .send({ identityId: id, privateKey: 'errada' });
      expect(r.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
    }
    expect(h.counters.get(`credrl:heartbeat:${serverIp}`)).toBeUndefined();
    expect(h.counters.get(`credfail:${id}`)).toBeGreaterThanOrEqual(5);
  }, 20000);
});
