import crypto from 'crypto';

/**
 * TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 dígitos) sem dependências externas,
 * compatível com Google Authenticator, Authy, 1Password etc.
 */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PERIOD_S = 30;
const DIGITS = 6;

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Segredo de 160 bits em base32 (o formato que os apps autenticadores esperam). */
export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = h[h.length - 1] & 0xf;
  const bin =
    ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function totpAt(secret: string, timeMs: number): string {
  return hotp(base32Decode(secret), Math.floor(timeMs / 1000 / PERIOD_S));
}

/**
 * Verifica o código aceitando ±`window` janelas (tolerância de relógio).
 * `lastCounter` é a última janela já aceita: um código dessa janela (ou de uma
 * anterior) é recusado, o que impede reutilizar um código interceptado.
 * Devolve a janela que bateu em `counter`.
 */
export function verifyTotp(
  secret: string,
  code: string,
  nowMs: number = Date.now(),
  opts: { lastCounter?: number; window?: number } = {}
): { ok: true; counter: number } | { ok: false; counter: undefined } {
  const fail = { ok: false as const, counter: undefined };
  if (!/^\d{6}$/.test(code)) return fail;
  const window = opts.window ?? 1;
  const key = base32Decode(secret);
  const current = Math.floor(nowMs / 1000 / PERIOD_S);
  const given = Buffer.from(code);
  let matched: number | null = null;
  // Percorre todas as janelas sem sair cedo, para não vazar qual bateu pelo tempo.
  for (let w = -window; w <= window; w++) {
    const expected = Buffer.from(hotp(key, current + w));
    if (crypto.timingSafeEqual(given, expected) && matched === null) matched = current + w;
  }
  if (matched === null) return fail;
  if (opts.lastCounter !== undefined && matched <= opts.lastCounter) return fail;
  return { ok: true, counter: matched };
}

export function otpauthUri(label: string, secret: string, issuer = 'Rekuway IDN'): string {
  const l = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${l}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${PERIOD_S}`;
}
