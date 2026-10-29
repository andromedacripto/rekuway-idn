import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const killIdentity = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock('../../src/config/database', () => ({ db: {} }));
vi.mock('../../src/services/identityService', () => ({
  killIdentity,
  regenerateIdentity: vi.fn(),
}));

import paranoiaConfig from '../../src/config/paranoia.json';
import { Identity } from '../../src/models/Identity';
import { checkDeadmanSwitch } from '../../src/services/defensiveService';

const NOW = new Date('2026-01-01T12:00:00Z').getTime();
const TIMER_MS = paranoiaConfig.deadman.deadmanTimer * 1000;

function make(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'dm-1',
    paranoiaLevel: 'deadman',
    isAlive: true,
    createdAt: NOW - 3_600_000,
    ...overrides,
  } as Identity;
}

describe('checkDeadmanSwitch', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    killIdentity.mockClear();
  });
  afterEach(() => vi.useRealTimers());

  it('timer do deadman é 60s', () => {
    expect(TIMER_MS).toBe(60_000);
  });

  it('ignora níveis que não são deadman', async () => {
    const id = make({ paranoiaLevel: 'high', lastHeartbeat: NOW - 10 * TIMER_MS });
    expect(await checkDeadmanSwitch(id)).toBe(false);
    expect(killIdentity).not.toHaveBeenCalled();
  });

  it('heartbeat dentro do prazo: não mata', async () => {
    expect(await checkDeadmanSwitch(make({ lastHeartbeat: NOW - (TIMER_MS - 1000) }))).toBe(false);
    expect(killIdentity).not.toHaveBeenCalled();
  });

  it('exatamente no limite ainda não mata (comparação estrita)', async () => {
    expect(await checkDeadmanSwitch(make({ lastHeartbeat: NOW - TIMER_MS }))).toBe(false);
  });

  it('heartbeat vencido: mata a identidade', async () => {
    expect(await checkDeadmanSwitch(make({ lastHeartbeat: NOW - (TIMER_MS + 1) }))).toBe(true);
    expect(killIdentity).toHaveBeenCalledWith('dm-1');
  });

  it('sem heartbeat usa lastCheckIn e depois createdAt', async () => {
    expect(await checkDeadmanSwitch(make({ lastCheckIn: NOW - 1000 }))).toBe(false);
    expect(await checkDeadmanSwitch(make({ lastCheckIn: NOW - TIMER_MS - 1 }))).toBe(true);
    expect(await checkDeadmanSwitch(make())).toBe(true);
  });
});
