import { beforeEach, describe, expect, it, vi } from 'vitest';

const m = vi.hoisted(() => ({
  store: new Map<string, unknown>(),
  killIdentity: vi.fn().mockResolvedValue(true),
  clearSession: vi.fn().mockResolvedValue(undefined),
  notifyDashboard: vi.fn(),
}));

vi.mock('../../src/config/database', () => ({
  db: {
    set: async (k: string, v: unknown) => (m.store.set(k, JSON.parse(JSON.stringify(v))), true),
    get: async (k: string) => m.store.get(k) ?? null,
    getIdentity: async (id: string) => m.store.get(`identity:${id}`) ?? null,
  },
}));
vi.mock('../../src/services/identityService', () => ({ killIdentity: m.killIdentity }));
vi.mock('../../src/services/sessionGuard', () => ({ clearSession: m.clearSession }));
vi.mock('../../src/services/dashboardEvents', () => ({ notifyDashboard: m.notifyDashboard }));

import { REUSE_GRACE_MS, handleTokenReuse, recordRotation } from '../../src/services/tokenReuse';

const ctx = { ip: '203.0.113.9', userAgent: 'UA-X' };
const T0 = 1_700_000_000_000;
const alive = () =>
  m.store.set('identity:id-1', { id: 'id-1', isAlive: true, userId: 'u1', paranoiaLevel: 'high' });

describe('detecção de reuso de token rotacionado', () => {
  beforeEach(() => {
    m.store.clear();
    vi.clearAllMocks();
  });

  it('token que nunca foi rotacionado: nada acontece', async () => {
    alive();
    expect(await handleTokenReuse('desconhecido', ctx, T0)).toBe('none');
    expect(m.killIdentity).not.toHaveBeenCalled();
  });

  it('a lápide guarda só identityId e instante, nunca segredo', async () => {
    await recordRotation('velho', 'id-1', T0 + 3_600_000, T0);
    expect(m.store.get('extused:velho')).toEqual({ identityId: 'id-1', at: T0 });
  });

  it('dentro da janela de tolerância (retry legítimo): ignora', async () => {
    alive();
    await recordRotation('velho', 'id-1', T0 + 3_600_000, T0);
    expect(await handleTokenReuse('velho', ctx, T0 + REUSE_GRACE_MS)).toBe('grace');
    expect(m.killIdentity).not.toHaveBeenCalled();
    expect(m.notifyDashboard).not.toHaveBeenCalled();
  });

  it('fora da janela: destrói a identidade e alerta como CRITICAL', async () => {
    alive();
    await recordRotation('velho', 'id-1', T0 + 3_600_000, T0);
    expect(await handleTokenReuse('velho', ctx, T0 + REUSE_GRACE_MS + 1)).toBe('revoked');
    expect(m.killIdentity).toHaveBeenCalledWith('id-1');
    expect(m.clearSession).toHaveBeenCalledWith('id-1');
    expect(m.notifyDashboard).toHaveBeenCalledTimes(1);
    expect(m.notifyDashboard.mock.calls[0][0]).toMatchObject({
      type: 'TOKEN_REUSE',
      severity: 'CRITICAL',
      blocked: true,
      userId: 'u1',
      ipAddress: ctx.ip,
    });
  });

  it('identidade já destruída: não repete o alerta', async () => {
    await recordRotation('velho', 'id-1', T0 + 3_600_000, T0);
    expect(await handleTokenReuse('velho', ctx, T0 + 60_000)).toBe('revoked');
    expect(m.killIdentity).not.toHaveBeenCalled();
    expect(m.notifyDashboard).not.toHaveBeenCalled();
  });
});
