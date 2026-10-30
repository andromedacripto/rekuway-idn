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
import { runDeadmanSweep } from '../../src/services/defensiveService';

let baseUrl = '';
let server: ReturnType<typeof app.listen>;
const SECRET = 'test-internal-secret-0123456789';

beforeAll(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  server.close();
});

describe('deadman: monitor automático avisa o dashboard', () => {
  it('manda o evento DEADMAN com o userId quando o prazo vence', async () => {
    const old = Date.now() - 10 * 60 * 1000;
    h.store.set('identity:dm-sweep-1', {
      id: 'dm-sweep-1',
      userId: 'user-xyz',
      paranoiaLevel: 'deadman',
      isAlive: true,
      createdAt: old,
      lastHeartbeat: old,
      lastCheckIn: old,
      expiresAt: Date.now() + 60_000,
      attempts: 0,
      suspiciousIPs: [],
    });
    const calls: Array<{ url: string; body: Record<string, unknown>; secret: string }> = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      if (String(url).includes('/api/keys/event')) {
        calls.push({
          url: String(url),
          body: JSON.parse(String(init?.body)),
          secret: String((init?.headers as Record<string, string>)['x-internal-secret']),
        });
        return new Response('{}');
      }
      return realFetch(url, init);
    }) as typeof fetch;
    try {
      const out = await runDeadmanSweep();
      expect(out.killed).toBe(1);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({ userId: 'user-xyz', type: 'DEADMAN', blocked: true });
    expect(calls[0].secret).toBe(SECRET);
    expect(String(calls[0].body.description)).toContain('dm-sweep-1');
  });
});
