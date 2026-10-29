import { describe, expect, it } from 'vitest';
import { getClientIp } from '../../src/utils/clientIp';

const req = (headers: Record<string, string | string[]>, remote?: string) =>
  ({ headers, socket: { remoteAddress: remote } }) as Parameters<typeof getClientIp>[0];

describe('getClientIp', () => {
  it('usa X-Real-IP do proxy confiável', () => {
    expect(getClientIp(req({ 'x-real-ip': '203.0.113.7' }, '10.0.0.1'))).toBe('203.0.113.7');
  });

  it('ignora X-Forwarded-For forjado', () => {
    const r = req({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }, '198.51.100.9');
    expect(getClientIp(r)).toBe('198.51.100.9');
  });

  it('rejeita X-Real-IP que não é um IP e cai no socket', () => {
    expect(getClientIp(req({ 'x-real-ip': 'não-é-ip' }, '198.51.100.9'))).toBe('198.51.100.9');
  });

  it('retorna unknown sem nenhuma fonte válida', () => {
    expect(getClientIp(req({}))).toBe('unknown');
  });
});
