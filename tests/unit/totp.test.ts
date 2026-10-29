import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  otpauthUri,
  totpAt,
  verifyTotp,
} from '../../src/utils/totp';

// Vetores do RFC 6238 (apêndice B), segredo ASCII "12345678901234567890", SHA-1.
// O RFC publica 8 dígitos; com 6 dígitos valem os 6 últimos.
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890'));

describe('TOTP (RFC 6238)', () => {
  it.each([
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ])('vetor do RFC em t=%i', (t, expected) => {
    expect(totpAt(RFC_SECRET, t * 1000)).toBe(expected);
  });

  it('base32 faz ida e volta', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Encode(base32Decode(secret))).toBe(secret);
  });

  it('aceita o código atual e ±1 passo, recusa fora da janela', () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000_000;
    expect(verifyTotp(secret, totpAt(secret, now), now).ok).toBe(true);
    expect(verifyTotp(secret, totpAt(secret, now - 30_000), now).ok).toBe(true);
    expect(verifyTotp(secret, totpAt(secret, now + 30_000), now).ok).toBe(true);
    expect(verifyTotp(secret, totpAt(secret, now - 120_000), now).ok).toBe(false);
  });

  it('impede replay do mesmo código', () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000_000;
    const first = verifyTotp(secret, totpAt(secret, now), now);
    expect(first.ok).toBe(true);
    const again = verifyTotp(secret, totpAt(secret, now), now, { lastCounter: first.counter });
    expect(again.ok).toBe(false);
  });

  it('recusa formato inválido', () => {
    const secret = generateTotpSecret();
    for (const bad of ['', '12345', '1234567', 'abcdef', '12 456']) {
      expect(verifyTotp(secret, bad, Date.now()).ok).toBe(false);
    }
  });

  it('gera URI otpauth', () => {
    const uri = otpauthUri('id-1', 'JBSWY3DPEHPK3PXP');
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('period=30');
  });
});
