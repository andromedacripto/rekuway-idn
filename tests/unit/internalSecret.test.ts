import { describe, expect, it } from 'vitest';
import { safeEqualSecret, validateInternalSecret } from '../../src/utils/internalSecret';

describe('validateInternalSecret', () => {
  it('recusa tudo quando INTERNAL_SECRET não está configurado (fail-closed)', () => {
    expect(validateInternalSecret(undefined, undefined)).toBe(false);
    expect(validateInternalSecret('undefined', undefined)).toBe(false);
    expect(validateInternalSecret('', '')).toBe(false);
    expect(validateInternalSecret('qualquer', '')).toBe(false);
  });

  it('aceita o segredo correto', () => {
    expect(validateInternalSecret('s3gredo-longo-123', 's3gredo-longo-123')).toBe(true);
  });

  it('recusa segredo errado, de outro tamanho, ausente ou vazio', () => {
    expect(validateInternalSecret('errado', 's3gredo-longo-123')).toBe(false);
    expect(validateInternalSecret('s3gredo-longo-12', 's3gredo-longo-123')).toBe(false);
    expect(validateInternalSecret(undefined, 's3gredo-longo-123')).toBe(false);
    expect(validateInternalSecret('', 's3gredo-longo-123')).toBe(false);
  });

  it('recusa cabeçalho repetido (array) ou tipo inesperado', () => {
    expect(validateInternalSecret(['s3gredo-longo-123'], 's3gredo-longo-123')).toBe(false);
    expect(validateInternalSecret(123, '123')).toBe(false);
  });

  it('lê process.env.INTERNAL_SECRET por padrão', () => {
    const original = process.env.INTERNAL_SECRET;
    try {
      delete process.env.INTERNAL_SECRET;
      expect(validateInternalSecret(undefined)).toBe(false);
      process.env.INTERNAL_SECRET = 'abc';
      expect(validateInternalSecret('abc')).toBe(true);
      expect(validateInternalSecret('abd')).toBe(false);
    } finally {
      if (original === undefined) delete process.env.INTERNAL_SECRET;
      else process.env.INTERNAL_SECRET = original;
    }
  });

  it('safeEqualSecret compartilha o mesmo comportamento fail-closed', () => {
    expect(safeEqualSecret('x', undefined)).toBe(false);
    expect(safeEqualSecret('x', 'x')).toBe(true);
  });
});
