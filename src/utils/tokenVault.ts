import crypto from 'crypto';

/**
 * Cofre de tokens: criptografa em repouso (AES-256-GCM) o token de credencial
 * que carrega a chave privada, para que um vazamento do Redis não entregue
 * identidades vivas.
 *
 * Chave: TOKEN_ENCRYPTION_KEY (64 hex = 32 bytes). Se ausente, deriva uma chave
 * de INTERNAL_SECRET via HKDF. Sem nenhuma das duas, falha (fail-closed): é
 * melhor não emitir token do que gravar a chave privada em claro.
 *
 * Formato: "v1:" + base64url(iv[12] | tag[16] | ciphertext). O identificador
 * do token externo entra como AAD, então um blob não pode ser trocado de
 * lugar no Redis.
 *
 * Valores antigos, sem o prefixo "v1:", são lidos como estão (migração):
 * eles expiram sozinhos pelo TTL da identidade.
 */
const PREFIX = 'v1:';

function getKey(): Buffer {
  const raw = process.env.TOKEN_ENCRYPTION_KEY;
  if (raw) {
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error('TOKEN_ENCRYPTION_KEY must be 64 hex characters');
    }
    return Buffer.from(raw, 'hex');
  }
  const secret = process.env.INTERNAL_SECRET;
  if (secret) {
    return Buffer.from(crypto.hkdfSync('sha256', secret, 'rekuway-idn', 'token-vault-v1', 32));
  }
  throw new Error('TOKEN_ENCRYPTION_KEY (or INTERNAL_SECRET) is not configured');
}

export function sealToken(plain: string, aad: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return PREFIX + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
}

/** Devolve o texto original, ou null se adulterado / chave errada. */
export function openToken(stored: string, aad: string): string | null {
  if (!stored.startsWith(PREFIX)) return stored; // legado (texto claro)
  try {
    const buf = Buffer.from(stored.slice(PREFIX.length), 'base64url');
    if (buf.length < 29) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), buf.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
