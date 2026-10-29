import { describe, expect, it, vi } from 'vitest';

vi.mock('../../src/services/apiKeyService', () => ({ validateApiKey: vi.fn() }));
vi.mock('../../src/utils/failureLimiter', () => ({ isBlocked: vi.fn(), recordFailure: vi.fn() }));

import type { Request } from 'express';
import {
  callerIp,
  callerUserAgent,
  isServerWithoutEndUserIp,
  parseEndUserContext,
} from '../../src/middleware/serverCaller';

const req = (over: Record<string, unknown> = {}) =>
  ({ headers: {}, socket: { remoteAddress: '10.9.9.9' }, ...over }) as unknown as Request;
const caller = (extra: Record<string, unknown> = {}) => ({ apiKey: {}, ...extra });

describe('contexto do usuário final (servidor autenticado)', () => {
  it('aceita IPv4 e IPv6 válidos e descarta o que não é IP', () => {
    expect(parseEndUserContext({ 'x-end-user-ip': '203.0.113.7' }).endUserIp).toBe('203.0.113.7');
    expect(parseEndUserContext({ 'x-end-user-ip': '2001:db8::1' }).endUserIp).toBe('2001:db8::1');
    for (const bad of ['', 'abc', '999.1.1.1', '1.2.3.4, 5.6.7.8', "1.1.1.1'; DROP"]) {
      expect(parseEndUserContext({ 'x-end-user-ip': bad }).endUserIp).toBeUndefined();
    }
  });

  it('corta o User-Agent em 256 caracteres e aceita cabeçalho repetido', () => {
    expect(
      parseEndUserContext({ 'x-end-user-user-agent': 'a'.repeat(1000) }).userAgent
    ).toHaveLength(256);
    expect(parseEndUserContext({ 'x-end-user-ip': ['198.51.100.1', '1.1.1.1'] }).endUserIp).toBe(
      '198.51.100.1'
    );
    expect(parseEndUserContext({}).userAgent).toBeUndefined();
  });

  it('sem chave válida, cabeçalhos são ignorados: vale a conexão', () => {
    const r = req({
      headers: {
        'x-real-ip': '198.51.100.20',
        'x-end-user-ip': '203.0.113.7',
        'user-agent': 'UA-conexao',
      },
    });
    expect(callerIp(r)).toBe('198.51.100.20');
    expect(callerUserAgent(r)).toBe('UA-conexao');
    expect(isServerWithoutEndUserIp(r)).toBe(false);
  });

  it('com chave válida, vale o contexto repassado', () => {
    const r = req({
      headers: { 'x-real-ip': '198.51.100.20', 'user-agent': 'UA-servidor' },
      serverCaller: caller({ endUserIp: '203.0.113.7', userAgent: 'UA-usuario' }),
    });
    expect(callerIp(r)).toBe('203.0.113.7');
    expect(callerUserAgent(r)).toBe('UA-usuario');
    expect(isServerWithoutEndUserIp(r)).toBe(false);
  });

  it('com chave válida mas sem IP repassado, avisa que o IP é do servidor', () => {
    const r = req({ headers: { 'x-real-ip': '198.51.100.20' }, serverCaller: caller() });
    expect(callerIp(r)).toBe('198.51.100.20');
    expect(isServerWithoutEndUserIp(r)).toBe(true);
  });
});
