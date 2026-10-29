import { describe, expect, it } from 'vitest';
import {
  isAction,
  isScope,
  patternCovers,
  scopeAllows,
  sensitiveWithinGranted,
  validateScopes,
} from '../../src/utils/agentScopes';

describe('escopos de agente', () => {
  it('aceita recurso:ação e curinga só no final', () => {
    for (const ok of ['db', 'db:read', 'db:orders:read', 'db:*', 'db:orders:*', 'a.b-c_d:x']) {
      expect(isScope(ok)).toBe(true);
    }
  });

  it('recusa acesso total, curinga no meio, maiúsculas, vazios e excessos', () => {
    for (const bad of [
      '*',
      ':*',
      'db:*:read',
      'DB:read',
      '',
      'db::read',
      'db read',
      'a:b:c:d:e',
      'x'.repeat(70),
    ]) {
      expect(isScope(bad)).toBe(false);
    }
    expect(isScope(42)).toBe(false);
  });

  it('ação concreta não pode ter curinga', () => {
    expect(isAction('db:read')).toBe(true);
    expect(isAction('db:*')).toBe(false);
  });

  it('curinga cobre o prefixo, mas não o recurso sozinho nem outro recurso', () => {
    expect(patternCovers('db:*', 'db:read')).toBe(true);
    expect(patternCovers('db:*', 'db:orders:read')).toBe(true);
    expect(patternCovers('db:*', 'db')).toBe(false);
    expect(patternCovers('db:*', 'dbx:read')).toBe(false);
    expect(patternCovers('db:orders:*', 'db:users:read')).toBe(false);
    expect(patternCovers('db:read', 'db:write')).toBe(false);
  });

  it('scopeAllows usa qualquer escopo concedido', () => {
    expect(scopeAllows(['files:read', 'db:*'], 'db:write')).toBe(true);
    expect(scopeAllows(['files:read'], 'db:write')).toBe(false);
  });

  it('valida listas', () => {
    expect(validateScopes(['db:read'])).toBeNull();
    expect(validateScopes([])).toMatch(/non-empty/);
    expect(validateScopes('db:read')).toMatch(/array/);
    expect(validateScopes(['db:read', 'db:read'])).toMatch(/duplicates/);
    expect(validateScopes(Array.from({ length: 21 }, (_, i) => `r${i}:x`))).toMatch(/at most/);
    expect(validateScopes(['*'])).toMatch(/invalid/);
  });

  it('sensível precisa estar dentro do concedido', () => {
    expect(sensitiveWithinGranted(['db:*'], ['db:write'])).toBe(true);
    expect(sensitiveWithinGranted(['db:read'], ['db:write'])).toBe(false);
    expect(sensitiveWithinGranted(['db:read'], ['db:*'])).toBe(false);
  });
});
