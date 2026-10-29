import { afterEach, describe, expect, it } from 'vitest';
import { openToken, sealToken } from '../../src/utils/tokenVault';

const KEY = 'a'.repeat(64);

describe('tokenVault', () => {
  afterEach(() => {
    delete process.env.TOKEN_ENCRYPTION_KEY;
    delete process.env.INTERNAL_SECRET;
  });

  it('cifra e decifra com AAD', () => {
    process.env.TOKEN_ENCRYPTION_KEY = KEY;
    const sealed = sealToken('segredo-com-chave-privada', 'tok1');
    expect(sealed.startsWith('v1:')).toBe(true);
    expect(sealed).not.toContain('segredo');
    expect(openToken(sealed, 'tok1')).toBe('segredo-com-chave-privada');
  });

  it('recusa AAD trocado, adulteração e chave diferente', () => {
    process.env.TOKEN_ENCRYPTION_KEY = KEY;
    const sealed = sealToken('x', 'tok1');
    expect(openToken(sealed, 'outro')).toBeNull();
    expect(openToken(sealed.slice(0, -2) + 'AA', 'tok1')).toBeNull();
    process.env.TOKEN_ENCRYPTION_KEY = 'b'.repeat(64);
    expect(openToken(sealed, 'tok1')).toBeNull();
  });

  it('deriva a chave de INTERNAL_SECRET quando TOKEN_ENCRYPTION_KEY falta', () => {
    process.env.INTERNAL_SECRET = 'segredo-interno';
    expect(openToken(sealToken('abc', 't'), 't')).toBe('abc');
  });

  it('falha fechado sem nenhuma chave configurada', () => {
    expect(() => sealToken('abc', 't')).toThrow();
  });

  it('aceita valores legados sem prefixo', () => {
    expect(openToken('texto-antigo', 't')).toBe('texto-antigo');
  });
});
