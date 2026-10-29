import crypto from 'crypto';
import { safeEqualString } from './internalSecret';

/**
 * Gera um par de chaves pública/privada
 * Usa RSA 2048 bits (padrão seguro)
 */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

/**
 * Cria hash SHA-256 de um valor
 * Usado para armazenar hash da chave privada sem expor o valor real
 */
export function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Gera um token aleatório
 * Usado como ID único da identidade
 */
export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Valida se uma chave privada corresponde ao hash armazenado
 */
export function validatePrivateKey(privateKey: string, storedHash: string): boolean {
  return safeEqualString(hashValue(privateKey), storedHash);
}

/**
 * Gera metadados falsos aleatórios
 * Usado quando sistema decide "mentir"
 */
export function generateFakeMetadata() {
  const fakeIPs = [
    '203.0.113.0', // Test network
    '198.51.100.0',
    '192.0.2.0',
  ];

  const fakeLocations = [
    'Tokyo, Japan',
    'London, UK',
    'Sydney, Australia',
    'São Paulo, Brazil',
    'Toronto, Canada',
  ];

  const fakeUserAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
  ];

  const fakeDevices = ['Desktop', 'Mobile', 'Tablet'];

  return {
    ip: fakeIPs[Math.floor(Math.random() * fakeIPs.length)],
    location: fakeLocations[Math.floor(Math.random() * fakeLocations.length)],
    userAgent: fakeUserAgents[Math.floor(Math.random() * fakeUserAgents.length)],
    device: fakeDevices[Math.floor(Math.random() * fakeDevices.length)],
  };
}
