import { describe, expect, it } from 'vitest';
// @ts-expect-error módulo .mjs sem tipos
import { scanFileName, scanText } from '../../scripts/secret-scan.mjs';

// Segredos falsos montados em tempo de execução: assim este arquivo não dispara o scanner.
const pem = (body: string) =>
  ['-----BEGIN ', 'PRIVATE KEY-----\n', body, '\n-----END ', 'PRIVATE KEY-----'].join('');
const BODY = 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj'.repeat(3);
const apiKey = (hex: string) => ['rkwy_', 'live_', hex].join('');

describe('scanner de segredos', () => {
  it('detecta bloco de chave privada completo, mas não o placeholder da documentação', () => {
    expect(scanText(pem(BODY), 'x.json')).toHaveLength(1);
    expect(scanText('"privateKey": "-----BEGIN PRIVATE KEY-----\\n..."', 'README.md')).toHaveLength(
      0
    );
  });

  it('detecta chave de API real e ignora exemplos de zeros', () => {
    expect(
      scanText(`const k = '${apiKey('a1b2c3d4e5f60718293a4b5c6d7e8f90')}'`, 'a.mjs')
    ).toHaveLength(1);
    expect(scanText(apiKey('0'.repeat(32)), 'PENTEST.md')).toHaveLength(0);
  });

  it('detecta variável secreta com valor em arquivo de ambiente, sem vazar o valor', () => {
    const f = scanText('INTERNAL_SECRET=abcdefgh12345678\n', '.env.prod');
    expect(f).toHaveLength(1);
    expect(f[0].sample).not.toContain('12345678');
  });

  it('aceita modelos vazios, placeholders e código que usa process.env', () => {
    expect(scanText('INTERNAL_SECRET=\nTOKEN_ENCRYPTION_KEY=\n', '.env.example')).toHaveLength(0);
    expect(scanText('INTERNAL_SECRET=$MEU_SEGREDO\n', 'run.sh')).toHaveLength(0);
    expect(scanText("process.env.INTERNAL_SECRET = 'abcdefgh12345678'", 'a.test.ts')).toHaveLength(
      0
    );
  });

  it('detecta tokens de provedores', () => {
    expect(scanText(['ghp', '_', 'a'.repeat(36)].join(''), 'a.txt')).toHaveLength(1);
    expect(scanText(['AKIA', 'ABCDEFGHIJKLMNOP'].join(''), 'a.txt')).toHaveLength(1);
  });

  it('recusa nomes de arquivo proibidos e libera os modelos', () => {
    for (const f of ['.env', 'config/.env.production', 'private.key', 'a/b/cert.pem', 'id_rsa']) {
      expect(scanFileName(f)).not.toBeNull();
    }
    for (const f of ['.env.example', 'ai-service/.env.example.txt', 'src/app.ts']) {
      expect(scanFileName(f)).toBeNull();
    }
  });
});
