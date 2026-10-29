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
import { decodeCredentialToken } from '../../src/routes/identityRoutes';
import { openToken } from '../../src/utils/tokenVault';
import { totpAt } from '../../src/utils/totp';
import { Rekuway, RekuwaySession } from '../../sdk/rekuway';

let baseUrl = '';
let server: ReturnType<typeof app.listen>;
let n = 0;
const nextIp = () => `192.0.2.${++n}`;
const SECRET = 'test-internal-secret-0123456789';
const client = (apiKey?: string, ip = nextIp()) =>
  new Rekuway({ baseUrl, apiKey, headers: { 'x-real-ip': ip } });

async function apiKey(): Promise<string> {
  const res = await fetch(`${baseUrl}/api-keys`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-internal-secret': SECRET,
      'x-real-ip': nextIp(),
    },
    body: JSON.stringify({ userId: 'sdk-user', name: 'sdk', tier: 'enterprise' }),
  });
  return (await res.json()).apiKey.key as string;
}

/** O SDK de propósito não expõe a chave privada; o teste a lê do Redis falso. */
function credentialsOf(token: string) {
  const plain = openToken(h.store.get(`ext:${token}`) as string, token)!;
  return decodeCredentialToken(plain)!;
}

beforeAll(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  server.close();
});

describe('SDK contra a API real', () => {
  it('cria sessão, valida e rotaciona o token sozinho', async () => {
    const ip = nextIp();
    const rk = client(await apiKey(), ip);
    const { session, mfa } = await rk.createSession('low');
    expect(mfa).toBeUndefined();
    const before = session.token;
    const r = await session.check();
    expect(r.status).toBe('allowed');
    expect(session.token).not.toBe(before);
    expect((await session.check()).status).toBe('allowed');
  });

  it('credencial inválida vira "denied", sem detalhes', async () => {
    const rk = client(await apiKey());
    const session = new RekuwaySession(rk, 'a'.repeat(64));
    expect((await session.check()).status).toBe('denied');
  });

  it('createIdentity sem chave válida falha com erro claro', async () => {
    await expect(client('rkwy_live_invalida').createIdentity('low')).rejects.toThrow(/not created/);
    await expect(client().createIdentity('low')).rejects.toThrow(/apiKey is required/);
  });

  it('risco: trava, falha, bloqueia, e o código certo destrava', async () => {
    const key = await apiKey();
    const ipA = nextIp();
    const { session, mfa } = await client(key, ipA).createSession('high');
    expect(mfa?.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect((await session.check()).status).toBe('allowed'); // IP A vira confiável

    // o mesmo token aparece em outro IP: risco
    const other = new RekuwaySession(client(key, nextIp()), session.token);
    const locked = await other.check();
    expect(locked.status).toBe('step_up_required');
    if (locked.status === 'step_up_required') expect(locked.methods).toEqual(['reauth', 'mfa']);

    const wrong = await other.stepUp('000000');
    expect(wrong).toEqual({ status: 'failed', remainingAttempts: 2 });

    const ok = await other.stepUp(totpAt(mfa!.secret, Date.now()));
    expect(ok.status).toBe('allowed');
    expect((await other.check()).status).toBe('allowed');
  }, 20000);

  it('falhas repetidas no desafio bloqueiam e informam quanto esperar', async () => {
    const key = await apiKey();
    const { session } = await client(key, nextIp()).createSession('high');
    await session.check();
    const other = new RekuwaySession(client(key, nextIp()), session.token);
    await other.check();
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await other.stepUp('111111'));
    expect(results.map((r) => r.status)).toEqual(['failed', 'failed', 'blocked']);
    const again = await other.check();
    expect(again.status).toBe('blocked');
    if (again.status === 'blocked') expect(again.retryAfterSeconds).toBeGreaterThan(0);
  }, 20000);

  it('stepUp sem desafio pendente explica o erro', async () => {
    const session = new RekuwaySession(client(await apiKey()), 'b'.repeat(64));
    await expect(session.stepUp('123456')).rejects.toThrow(/no pending challenge/);
  });

  it('heartbeat, regenerate e kill com a credencial', async () => {
    const key = await apiKey();
    const rk = client(key, nextIp());
    const { session } = await rk.createSession('deadman');
    const { identityId, privateKey } = credentialsOf(session.token);

    expect(await rk.heartbeat(identityId, 'chave-errada')).toBe(false);
    expect(await rk.heartbeat(identityId, privateKey)).toBe(true);

    const fresh = await rk.regenerate(identityId, privateKey);
    expect(fresh).not.toBeNull();
    expect(fresh!.identityId).not.toBe(identityId);
    expect(fresh!.level).toBe('deadman');

    expect(await rk.kill(fresh!.identityId, 'chave-errada')).toBe(false);
    expect(await rk.kill(fresh!.identityId, fresh!.privateKey)).toBe(true);
    expect(await rk.kill(fresh!.identityId, fresh!.privateKey)).toBe(false); // já destruída
  }, 20000);

  it('token antigo reapresentado (roubo) derruba a identidade e o SDK vê "denied"', async () => {
    const rk = client(await apiKey(), nextIp());
    const { session } = await rk.createSession('low');
    const stale = session.token;
    expect((await session.check()).status).toBe('allowed'); // troca o token
    (h.store.get(`extused:${stale}`) as { at: number }).at -= 60_000;

    const thief = new RekuwaySession(client(undefined, nextIp()), stale);
    expect((await thief.check()).status).toBe('denied');
    expect((await session.check()).status).toBe('denied'); // dono também perde: precisa de nova identidade
  }, 20000);

  it('servidor repassa o contexto do usuário: IP novo trava, e sem contexto não', async () => {
    const rk = client(await apiKey(), nextIp());
    const { session } = await rk.createSession('medium');
    expect((await session.check({ ip: '203.0.113.50', userAgent: 'UA-A' })).status).toBe('allowed');
    const risky = await session.check({ ip: '203.0.113.77', userAgent: 'UA-A' });
    expect(risky.status).toBe('step_up_required');

    const other = await client(await apiKey(), nextIp()).createSession('medium');
    expect((await other.session.check()).status).toBe('allowed');
    expect((await other.session.check()).status).toBe('allowed');
  }, 20000);
});
