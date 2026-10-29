import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
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
import { decodeCredentialToken } from '../../src/routes/identityRoutes';
import { openToken } from '../../src/utils/tokenVault';
import { totpAt } from '../../src/utils/totp';

const SECRET = { 'x-internal-secret': 'test-internal-secret-0123456789' };
let n = 0;
const ip = () => `203.0.113.${++n}`; // IP novo por teste: o rate limit é por IP

async function newApiKey(realIp: string): Promise<string> {
  const res = await request(app)
    .post('/api-keys')
    .set(SECRET)
    .set('x-real-ip', realIp)
    .send({ userId: 'user-1', name: 'test', tier: 'enterprise' });
  expect(res.status).toBe(201);
  return res.body.apiKey.key as string;
}

async function newIdentity(key: string, realIp: string, level = 'high') {
  const res = await request(app)
    .post('/identity/new')
    .set('Authorization', `Bearer ${key}`)
    .set('x-real-ip', realIp)
    .send({ paranoiaLevel: level });
  return res;
}

beforeAll(() => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
});

beforeEach(() => {
  h.redisDown.value = false;
});

describe('CORS', () => {
  it('libera somente origens de ALLOWED_ORIGINS', async () => {
    const ok = await request(app)
      .get('/health')
      .set('x-real-ip', ip())
      .set('Origin', 'https://app.rekuway.test');
    expect(ok.headers['access-control-allow-origin']).toBe('https://app.rekuway.test');

    const bad = await request(app)
      .get('/health')
      .set('x-real-ip', ip())
      .set('Origin', 'https://evil.example');
    expect(bad.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('/api-keys exige segredo interno', () => {
  it('recusa sem segredo e com segredo errado', async () => {
    const a = await request(app)
      .post('/api-keys')
      .set('x-real-ip', ip())
      .send({ userId: 'u', name: 'n' });
    expect(a.status).toBe(401);
    const b = await request(app)
      .delete('/api-keys/abc')
      .set('x-real-ip', ip())
      .set('x-internal-secret', 'errado');
    expect(b.status).toBe(401);
    const c = await request(app).get('/api-keys/user-1').set('x-real-ip', ip());
    expect(c.status).toBe(401);
  });

  it('aceita com o segredo correto', async () => {
    const key = await newApiKey(ip());
    expect(key.startsWith('rkwy_live_')).toBe(true);
  });
});

describe('fluxo de identidade', () => {
  it('cria, guarda o token criptografado, valida e rotaciona', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    const created = await newIdentity(key, realIp);
    expect(created.body.status).toBe('created');
    const token = created.body.token as string;
    expect(token).toMatch(/^[0-9a-f]{64}$/);

    // No Redis o token não pode conter a chave privada em claro (nem em base64).
    const stored = h.store.get(`ext:${token}`) as string;
    expect(stored.startsWith('v1:')).toBe(true);
    const asText = Buffer.from(stored.slice(3), 'base64url').toString('latin1');
    expect(stored).not.toContain('PRIVATE');
    expect(asText).not.toContain('PRIVATE');

    const ok = await request(app).post('/identity/check').set('x-real-ip', realIp).send({ token });
    expect(ok.body.action).toBe('ALLOWED');
    const rotated = ok.body.token as string;
    expect(rotated).toMatch(/^[0-9a-f]{64}$/);
    expect(rotated).not.toBe(token);

    // Token antigo morre; o novo funciona.
    const old = await request(app).post('/identity/check').set('x-real-ip', realIp).send({ token });
    expect(old.body.action).toBeUndefined();
    const next = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ token: rotated });
    expect(next.body.action).toBe('ALLOWED');
  });

  it('ignora a chave de API passada na URL', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    const res = await request(app)
      .post(`/identity/new?apiKey=${key}`)
      .set('x-real-ip', realIp)
      .send({ paranoiaLevel: 'low' });
    expect(res.body.token).toBeUndefined();
  });

  it('chave privada errada em deadman: resposta uniforme e a identidade é destruída', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    const created = await newIdentity(key, realIp, 'deadman');
    const id = [...h.store.keys()]
      .filter((k) => k.startsWith('identity:'))
      .pop()!
      .slice(9);
    expect(created.body.token).toBeDefined();

    const res = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ identityId: id, privateKey: 'chave-errada' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
    expect(h.store.get(`identity:${id}`)).toBeUndefined();
  });
});

describe('heartbeat / regenerate / kill', () => {
  it('chave errada devolve resposta stealth (não 401) e bloqueia após falhas repetidas', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    await newIdentity(key, realIp, 'deadman');
    const id = [...h.store.keys()]
      .filter((k) => k.startsWith('identity:'))
      .pop()!
      .slice(9);

    for (let i = 0; i < 5; i++) {
      const bad = await request(app)
        .post('/identity/heartbeat')
        .set('x-real-ip', `198.51.100.${i + 1}`) // IPs diferentes: só o limite por identidade vale
        .send({ identityId: id, privateKey: 'errada' });
      expect(bad.status).toBe(200);
      expect(bad.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
    }
    expect(h.counters.get(`credfail:${id}`)).toBe(5);
  });

  it('kill e regenerate com chave inválida não revelam nada', async () => {
    const id = '11111111-1111-4111-8111-111111111111';
    for (const route of ['kill', 'regenerate']) {
      const res = await request(app)
        .post(`/identity/${route}`)
        .set('x-real-ip', ip())
        .send({ identityId: id, privateKey: 'x' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
    }
  });
});

describe('rate limit', () => {
  it('ignora X-Forwarded-For forjado: o limite vale por X-Real-IP', async () => {
    const realIp = ip();
    let blocked = 0;
    for (let i = 0; i < 12; i++) {
      const res = await request(app)
        .get('/health')
        .set('x-real-ip', realIp)
        .set('x-forwarded-for', `9.9.9.${i}`);
      if (res.body.mode === 'stealth') blocked++;
    }
    expect(blocked).toBe(2);
  });

  it('Redis fora do ar: leitura passa (fail-open), rota sensível é recusada (fail-closed)', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    h.redisDown.value = true;

    const read = await request(app).get('/health').set('x-real-ip', ip());
    expect(read.body.status).toBe('ok');
    expect(read.body.mode).toBeUndefined();

    const write = await request(app)
      .post('/identity/new')
      .set('Authorization', `Bearer ${key}`)
      .set('x-real-ip', ip())
      .send({ paranoiaLevel: 'low' });
    expect(write.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
  }, 15000);
});

describe('/internal', () => {
  it('stats e deadman-sweep recusam sem credencial', async () => {
    expect((await request(app).get('/internal/stats').set('x-real-ip', ip())).status).toBe(401);
    expect((await request(app).get('/internal/deadman-sweep').set('x-real-ip', ip())).status).toBe(
      401
    );
  });

  it('deadman-sweep aceita x-internal-secret ou Bearer CRON_SECRET', async () => {
    const a = await request(app).get('/internal/deadman-sweep').set(SECRET).set('x-real-ip', ip());
    expect(a.status).toBe(200);
    expect(a.body).toHaveProperty('killed');
    const b = await request(app)
      .get('/internal/deadman-sweep')
      .set('Authorization', 'Bearer test-cron-secret-0123456789')
      .set('x-real-ip', ip());
    expect(b.status).toBe(200);
  });

  it('o sweep destrói deadman vencido', async () => {
    const realIp = ip();
    const key = await newApiKey(realIp);
    await newIdentity(key, realIp, 'deadman');
    const id = [...h.store.keys()]
      .filter((k) => k.startsWith('identity:'))
      .pop()!
      .slice(9);
    const identity = h.store.get(`identity:${id}`) as Record<string, number>;
    identity.lastHeartbeat = Date.now() - 120_000;
    identity.lastCheckIn = Date.now() - 120_000;

    const res = await request(app)
      .get('/internal/deadman-sweep')
      .set(SECRET)
      .set('x-real-ip', ip());
    expect(res.body.killed).toBeGreaterThanOrEqual(1);
    expect(h.store.get(`identity:${id}`)).toBeUndefined();
  });
});

describe('erros', () => {
  it('JSON malformado recebe resposta uniforme', async () => {
    const res = await request(app)
      .post('/identity/check')
      .set('x-real-ip', ip())
      .set('Content-Type', 'application/json')
      .send('{ não é json');
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('stealth');
  });
});

// ─────────────────────────────────────────────
//  Bloqueio de sessão (step-up, MFA, bloqueio)
// ─────────────────────────────────────────────
describe('bloqueio de sessão', () => {
  const STEALTH = { success: true, status: 'ok', mode: 'stealth' };

  async function setup(level: string) {
    const ipA = ip();
    const key = await newApiKey(ipA);
    const created = await newIdentity(key, ipA, level);
    const token = created.body.token as string;
    const plain = openToken(h.store.get(`ext:${token}`) as string, token)!;
    const { identityId, privateKey } = decodeCredentialToken(plain)!;
    return { ipA, token, identityId, privateKey, mfa: created.body.mfa };
  }
  const check = (token: string, realIp: string) =>
    request(app).post('/identity/check').set('x-real-ip', realIp).send({ token });

  it('MFA é emitido nos níveis que exigem (high, deadman) e não no low', async () => {
    const high = await setup('high');
    expect(high.mfa.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(high.mfa.otpauthUri).toContain('otpauth://totp/');
    // O segredo não fica em claro no Redis.
    const stored = h.store.get(`identity:${high.identityId}`) as { mfaSecret: string };
    expect(stored.mfaSecret.startsWith('v1:')).toBe(true);
    expect(JSON.stringify(stored)).not.toContain(high.mfa.secret);
    expect((await setup('low')).mfa).toBeUndefined();
  });

  it('IP diferente com credencial válida trava a sessão e exige step-up', async () => {
    const s = await setup('high');
    const first = await check(s.token, s.ipA);
    expect(first.body.action).toBe('ALLOWED');
    s.token = first.body.token;

    const res = await check(s.token, ip());
    expect(res.body.action).toBe('STEP_UP_REQUIRED');
    expect(res.body.methods).toEqual(['reauth', 'mfa']);
    expect(res.body.challengeId).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.body.token).toBeUndefined();

    // Enquanto travada, o dono também fica de fora, mesmo voltando ao IP original.
    expect((await check(s.token, s.ipA)).body.action).toBe('STEP_UP_REQUIRED');
  });

  it('nível low tolera um IP diferente sozinho', async () => {
    const s = await setup('low');
    s.token = (await check(s.token, s.ipA)).body.token;
    const res = await check(s.token, ip());
    expect(res.body.action).toBe('ALLOWED');
  });

  it('sessão travada não renova o deadman (heartbeat recusado)', async () => {
    const s = await setup('deadman');
    s.token = (await check(s.token, s.ipA)).body.token;
    expect((await check(s.token, ip())).body.action).toBe('STEP_UP_REQUIRED');

    const hb = await request(app)
      .post('/identity/heartbeat')
      .set('x-real-ip', ip())
      .send({ identityId: s.identityId, privateKey: s.privateKey });
    expect(hb.body).toEqual(STEALTH);
  });

  it('heartbeat de IP novo trava a sessão em vez de renovar o deadman', async () => {
    const s = await setup('deadman');
    s.token = (await check(s.token, s.ipA)).body.token;
    const beat = (realIp: string) =>
      request(app)
        .post('/identity/heartbeat')
        .set('x-real-ip', realIp)
        .send({ identityId: s.identityId, privateKey: s.privateKey });

    const ok = await beat(s.ipA);
    expect(ok.body.success).toBe(true);
    expect(ok.body.identity.remainingSeconds).toBeGreaterThan(0);

    const stolen = await beat(ip());
    expect(stolen.body).toEqual(STEALTH);
    expect((await check(s.token, s.ipA)).body.action).toBe('STEP_UP_REQUIRED');
  });

  it('step-up com MFA correto libera, entrega token novo e vira o novo ponto de partida', async () => {
    const s = await setup('high');
    s.token = (await check(s.token, s.ipA)).body.token;
    const ipB = ip();
    const challenge = (await check(s.token, ipB)).body;

    const ok = await request(app)
      .post('/identity/step-up')
      .set('x-real-ip', ipB)
      .send({
        token: s.token,
        challengeId: challenge.challengeId,
        code: totpAt(s.mfa.secret, Date.now()),
      });
    expect(ok.body.action).toBe('ALLOWED');
    expect(ok.body.token).toMatch(/^[0-9a-f]{64}$/);

    // O IP novo agora é a referência: o uso seguinte passa.
    const next = await check(ok.body.token, ipB);
    expect(next.body.action).toBe('ALLOWED');
  });

  it('o mesmo código MFA não vale duas vezes (anti-replay)', async () => {
    const s = await setup('high');
    s.token = (await check(s.token, s.ipA)).body.token;
    const code = totpAt(s.mfa.secret, Date.now());
    const stepUp = (token: string, challengeId: string, realIp: string) =>
      request(app)
        .post('/identity/step-up')
        .set('x-real-ip', realIp)
        .send({ token, challengeId, code });

    const ipB = ip();
    const c1 = (await check(s.token, ipB)).body;
    const first = await stepUp(s.token, c1.challengeId, ipB);
    expect(first.body.action).toBe('ALLOWED');

    // Fim da carência + outro IP: nova trava. O mesmo código interceptado não serve.
    (h.store.get(`session:${s.identityId}`) as Record<string, number>).trustedUntil =
      Date.now() - 1000;
    const ipC = ip();
    const c2 = (await check(first.body.token, ipC)).body;
    expect(c2.action).toBe('STEP_UP_REQUIRED');
    const replay = await stepUp(first.body.token, c2.challengeId, ipC);
    expect(replay.body.action).toBe('STEP_UP_FAILED');
  });

  it('código errado repetido bloqueia a sessão; depois o desbloqueio de suporte libera', async () => {
    const s = await setup('high'); // 3 falhas toleradas
    s.token = (await check(s.token, s.ipA)).body.token;
    const ipB = ip();
    const challenge = (await check(s.token, ipB)).body;
    const wrong = () =>
      request(app)
        .post('/identity/step-up')
        .set('x-real-ip', ipB)
        .send({ token: s.token, challengeId: challenge.challengeId, code: '000000' });

    expect((await wrong()).body).toMatchObject({ action: 'STEP_UP_FAILED', remainingAttempts: 2 });
    expect((await wrong()).body).toMatchObject({ action: 'STEP_UP_FAILED', remainingAttempts: 1 });
    const blocked = await wrong();
    expect(blocked.body.action).toBe('BLOCKED');
    expect(blocked.body.retryAfter).toBeGreaterThan(0);

    expect((await check(s.token, ipB)).body.action).toBe('BLOCKED');

    // Sem credencial interna não desbloqueia.
    const denied = await request(app)
      .post(`/internal/identities/${s.identityId}/unlock`)
      .set('x-real-ip', ip());
    expect(denied.status).toBe(401);

    const unlock = await request(app)
      .post(`/internal/identities/${s.identityId}/unlock`)
      .set(SECRET)
      .set('x-real-ip', ip());
    expect(unlock.body.success).toBe(true);
    expect((await check(s.token, ipB)).body.action).toBe('ALLOWED');
  });

  it('bloqueio repetido dura o dobro', async () => {
    const s = await setup('high');
    s.token = (await check(s.token, s.ipA)).body.token;
    const ipB = ip();
    const challenge = (await check(s.token, ipB)).body;
    const wrong = () =>
      request(app)
        .post('/identity/step-up')
        .set('x-real-ip', ipB)
        .send({ token: s.token, challengeId: challenge.challengeId, code: '000000' });
    await wrong();
    await wrong();
    const first = (await wrong()).body.retryAfter as number;
    expect(first).toBeLessThanOrEqual(1800);
    expect(first).toBeGreaterThan(1700);

    // Simula o fim do bloqueio: volta ao desafio (não ao acesso livre) com novo id.
    const rec = h.store.get(`session:${s.identityId}`) as Record<string, unknown>;
    rec.blockedUntil = Date.now() - 1000;
    const again = (await check(s.token, ipB)).body;
    expect(again.action).toBe('STEP_UP_REQUIRED');
    expect(again.challengeId).not.toBe(challenge.challengeId);

    const wrong2 = () =>
      request(app)
        .post('/identity/step-up')
        .set('x-real-ip', ipB)
        .send({ token: s.token, challengeId: again.challengeId, code: '000000' });
    await wrong2();
    await wrong2();
    const second = (await wrong2()).body.retryAfter as number;
    expect(second).toBeGreaterThan(3500);
    expect(second).toBeLessThanOrEqual(3600);
  });

  it('deadman: se o desafio persiste em falhar, a identidade é destruída', async () => {
    const s = await setup('deadman'); // 2 falhas toleradas, onPersist = kill
    s.token = (await check(s.token, s.ipA)).body.token;
    const ipB = ip();
    const challenge = (await check(s.token, ipB)).body;
    const wrong = () =>
      request(app)
        .post('/identity/step-up')
        .set('x-real-ip', ipB)
        .send({ token: s.token, challengeId: challenge.challengeId, code: '000000' });
    expect((await wrong()).body.action).toBe('STEP_UP_FAILED');
    const last = await wrong();
    expect(last.body).toEqual(STEALTH);
    expect(h.store.get(`identity:${s.identityId}`)).toBeUndefined();
  });

  it('quem não tem a credencial não consegue travar nem ver o desafio', async () => {
    const s = await setup('high');
    s.token = (await check(s.token, s.ipA)).body.token;
    // Atacante sem credencial insistindo de vários IPs só recebe a resposta uniforme.
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post('/identity/check')
        .set('x-real-ip', ip())
        .send({ identityId: s.identityId, privateKey: 'chave-errada' });
      expect(res.body.action).toBeUndefined();
    }
    expect(h.store.get(`session:${s.identityId}`)).toBeUndefined();
  });
});

// ───────────────────────────────────────────────────────────────
//  Reuso de token rotacionado (roubo de token)
// ───────────────────────────────────────────────────────────────
describe('reuso de token rotacionado', () => {
  async function twoChecks() {
    const realIp = ip();
    const key = await newApiKey(realIp);
    const created = await newIdentity(key, realIp, 'low');
    const id = [...h.store.keys()]
      .filter((k) => k.startsWith('identity:'))
      .pop()!
      .slice(9);
    const t1 = created.body.token as string;
    const first = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ token: t1 });
    return { realIp, id, t1, t2: first.body.token as string };
  }

  it('reuso imediato (retry/paralelismo) é tolerado e não destrói nada', async () => {
    const { realIp, id, t1, t2 } = await twoChecks();
    const retry = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ token: t1 });
    expect(retry.body).toEqual({ success: true, status: 'ok', mode: 'stealth' });
    expect(h.store.get(`identity:${id}`)).toBeDefined();
    const ok = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ token: t2 });
    expect(ok.body.action).toBe('ALLOWED');
  });

  it('token antigo reapresentado depois da janela destrói a identidade e alerta', async () => {
    const { realIp, id, t1, t2 } = await twoChecks();
    // envelhece a lápide para além da janela de tolerância
    (h.store.get(`extused:${t1}`) as { at: number }).at -= 60_000;
    (globalThis.fetch as unknown as { mockClear: () => void }).mockClear();

    const thief = await request(app)
      .post('/identity/check')
      .set('x-real-ip', ip())
      .send({ token: t1 });
    expect(thief.body).toEqual({ success: true, status: 'ok', mode: 'stealth' }); // não revela nada
    expect(h.store.get(`identity:${id}`)).toBeUndefined();

    // o token "novo" que o dono tinha também deixou de funcionar
    const owner = await request(app)
      .post('/identity/check')
      .set('x-real-ip', realIp)
      .send({ token: t2 });
    expect(owner.body.action).toBeUndefined();

    const calls = (globalThis.fetch as unknown as { mock: { calls: [string, { body: string }][] } })
      .mock.calls;
    const events = calls
      .map(([, init]) => JSON.parse(init.body))
      .filter((e) => e.type === 'TOKEN_REUSE');
    expect(events).toHaveLength(1);
    expect(events[0].severity).toBe('CRITICAL');
  });
});
