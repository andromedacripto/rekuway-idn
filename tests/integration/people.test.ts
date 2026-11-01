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
import app from '../../src/app';
import { Rekuway } from '../../sdk/rekuway';
import { createIdentity, regenerateIdentity } from '../../src/services/identityService';

const SECRET = 'test-internal-secret-0123456789';
let baseUrl = '';
let server: ReturnType<typeof app.listen>;
let rkA: Rekuway; // empresa A
let rkB: Rekuway; // empresa B
const events: Array<Record<string, any>> = [];

async function newKey(userId: string): Promise<string> {
  const res = await fetch(`${baseUrl}/api-keys`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-secret': SECRET },
    body: JSON.stringify({ userId, name: userId, tier: 'enterprise' }),
  });
  return (await res.json()).apiKey.key;
}

beforeAll(async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/api/keys/event')) {
      events.push(JSON.parse(String(init?.body)));
      return new Response('{}');
    }
    return realFetch(url, init);
  }) as typeof fetch;
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  rkA = new Rekuway({ baseUrl, apiKey: await newKey('empresa-a') });
  rkB = new Rekuway({ baseUrl, apiKey: await newKey('empresa-b') });
});
afterAll(() => {
  server.close();
});

describe('pessoa (externalRef)', () => {
  it('o evento de criação carrega o código da pessoa', async () => {
    await rkA.createSession('medium', { externalRef: 'func-evt' });
    const ev = events.find(
      (e) => e.type === 'IDENTITY_CREATED' && e.metadata?.externalRef === 'func-evt'
    );
    expect(ev?.userId).toBe('empresa-a');
  });

  it('código com ":" ou curinga é recusado', async () => {
    await expect(rkA.createIdentity('medium', { externalRef: 'a:b' })).rejects.toThrow();
    await expect(rkA.createIdentity('medium', { externalRef: '*' })).rejects.toThrow();
  });

  it('eventos de risco também carregam o código da pessoa', async () => {
    const { session } = await rkA.createSession('medium', { externalRef: 'func-risco' });
    await session.check({ ip: '203.0.113.10', userAgent: 'Chrome' });
    await session.check({ ip: '203.0.113.10', userAgent: 'Chrome' });
    const r = await session.check({ ip: '198.18.0.50', userAgent: 'Chrome' });
    expect(r.status).toBe('step_up_required');
    const ev = events.find(
      (e) => e.type === 'SESSION_LOCKED' && e.metadata?.externalRef === 'func-risco'
    );
    expect(ev?.userId).toBe('empresa-a');
  });

  it('revokePerson destrói só as identidades daquela pessoa', async () => {
    const a1 = await rkA.createSession('medium', { externalRef: 'func-1' });
    const a2 = await rkA.createSession('low', { externalRef: 'func-1' });
    const outra = await rkA.createSession('medium', { externalRef: 'func-2' });
    const ctx = { ip: '203.0.113.20', userAgent: 'Chrome' };
    expect((await a1.session.check(ctx)).status).toBe('allowed');

    const out = await rkA.revokePerson('func-1');
    expect(out.revoked).toBe(2);

    expect((await a1.session.check(ctx)).status).toBe('denied');
    expect((await a2.session.check(ctx)).status).toBe('denied');
    expect((await outra.session.check(ctx)).status).toBe('allowed');
    expect(events.some((e) => e.type === 'REVOKE' && e.metadata?.externalRef === 'func-1')).toBe(
      true
    );
  });

  it('uma empresa não revoga a pessoa de outra, mesmo com o mesmo código', async () => {
    const a = await rkA.createSession('medium', { externalRef: 'mesmo-codigo' });
    const b = await rkB.createSession('medium', { externalRef: 'mesmo-codigo' });
    const ctx = { ip: '203.0.113.30', userAgent: 'Chrome' };

    expect((await rkB.revokePerson('mesmo-codigo')).revoked).toBe(1);
    expect((await b.session.check(ctx)).status).toBe('denied');
    expect((await a.session.check(ctx)).status).toBe('allowed');
  });

  it('revogar uma pessoa sem identidades devolve 0', async () => {
    expect((await rkA.revokePerson('ninguem')).revoked).toBe(0);
  });

  it('rota interna do dashboard exige o segredo e respeita a empresa', async () => {
    const alvo = await rkA.createSession('medium', { externalRef: 'func-int' });
    const url = `${baseUrl}/internal/people/revoke`;
    const sem = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'empresa-a', externalRef: 'func-int' }),
    });
    expect(sem.status).toBe(401);
    const outraEmpresa = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': SECRET },
      body: JSON.stringify({ userId: 'empresa-b', externalRef: 'func-int' }),
    });
    expect((await outraEmpresa.json()).revoked).toBe(0);
    const ok = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': SECRET },
      body: JSON.stringify({ userId: 'empresa-a', externalRef: 'func-int' }),
    });
    expect((await ok.json()).revoked).toBe(1);
    expect((await alvo.session.check({ ip: '203.0.113.40' })).status).toBe('denied');
  });

  it('a identidade regenerada continua sendo da mesma empresa e pessoa', async () => {
    const { identity } = await createIdentity('medium');
    identity.userId = 'empresa-a';
    identity.externalRef = 'func-regen';
    const { db } = await import('../../src/config/database');
    await db.setIdentity(identity.id, identity);
    const novo = await regenerateIdentity(identity.id);
    expect(novo?.identity.userId).toBe('empresa-a');
    expect(novo?.identity.externalRef).toBe('func-regen');
    expect((await rkA.revokePerson('func-regen')).revoked).toBe(1);
  });
});
