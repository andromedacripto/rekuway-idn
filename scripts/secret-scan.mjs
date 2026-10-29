#!/usr/bin/env node
/**
 * Scanner de segredos (sem dependências).
 *
 *   node scripts/secret-scan.mjs --staged     arquivos em stage (hook de pre-commit)
 *   node scripts/secret-scan.mjs --all        todos os arquivos versionados
 *   node scripts/secret-scan.mjs --history    todo blob de todo o histórico
 *
 * Sai com código 1 se achar algo. Nunca imprime o segredo: só arquivo, linha,
 * tipo e os primeiros caracteres mascarados.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

/** Nomes de arquivo que nunca devem ser versionados. */
export const FORBIDDEN_FILES = [
  /(^|\/)\.env(\.[\w-]+)?$/, // .env, .env.local, .env.production…
  /\.(pem|key|p12|pfx|jks)$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/,
];
const FILE_ALLOWLIST = [/(^|\/)\.env\.example(\.txt)?$/];

/** Padrões de conteúdo. `test` pode recusar placeholders óbvios. */
export const PATTERNS = [
  {
    name: 'bloco de chave privada',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s\\n]{60,}?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    name: 'chave de API Rekuway',
    re: /rkwy_(?:live|test)_[0-9a-f]{32}/g,
    test: (m) => !/^rkwy_\w+_(.)\1+$/.test(m), // 0000… e similares são exemplos
  },
  { name: 'token do GitHub', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { name: 'chave de acesso AWS', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'chave sk-', re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { name: 'token do Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  {
    // VARIAVEL=valor em arquivos de ambiente / shell (não pega process.env.X = '…' em código)
    name: 'variável secreta com valor',
    re: /^(?:export\s+)?(UPSTASH_REDIS_REST_TOKEN|INTERNAL_SECRET|JWT_SECRET|TOKEN_ENCRYPTION_KEY|AI_SERVICE_TOKEN|CRON_SECRET|IPAPI_PRO_KEY|SNYK_TOKEN)\s*=\s*['"]?([^\s'"#]{8,})/gm,
    test: (m) => !/=\s*['"]?(?:\$|<|your|changeme|xxx)/i.test(m),
  },
];

const mask = (s) => `${s.slice(0, 6)}…(${s.length} car.)`;

/** @returns {{ line: number, type: string, sample: string }[]} */
export function scanText(text, file = '') {
  if (FILE_ALLOWLIST.some((re) => re.test(file))) return [];
  const findings = [];
  for (const { name, re, test } of PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      if (test && !test(m[0])) continue;
      const line = text.slice(0, m.index).split('\n').length;
      findings.push({ line, type: name, sample: mask(m[0]) });
    }
  }
  return findings;
}

export function scanFileName(file) {
  if (FILE_ALLOWLIST.some((re) => re.test(file))) return null;
  return FORBIDDEN_FILES.some((re) => re.test(file)) ? 'arquivo que não deve ser versionado' : null;
}

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 28 });
const isBinary = (buf) => buf.subarray(0, 8000).includes(0);
const MAX_BYTES = 2_000_000;

function report(where, findings) {
  for (const f of findings) console.error(`  ${where}${f.line ? `:${f.line}` : ''}  ${f.type}  ${f.sample}`);
  return findings.length;
}

function scanFiles(files, read) {
  let total = 0;
  for (const file of files) {
    const nameIssue = scanFileName(file);
    if (nameIssue) total += report(file, [{ line: 0, type: nameIssue, sample: '' }]);
    let buf;
    try {
      buf = read(file);
    } catch {
      continue;
    }
    if (!buf || buf.length > MAX_BYTES || isBinary(buf)) continue;
    total += report(file, scanText(buf.toString('utf8'), file));
  }
  return total;
}

function scanHistory() {
  // Cada blob único de qualquer commit, com um dos caminhos em que apareceu.
  const objs = git('rev-list', '--objects', '--all')
    .split('\n')
    .filter((l) => l.includes(' '))
    .map((l) => [l.slice(0, 40), l.slice(41)]);
  const types = spawnSync('git', ['cat-file', '--batch-check=%(objectname) %(objecttype)'], {
    input: objs.map(([id]) => id).join('\n') + '\n',
    encoding: 'utf8',
    maxBuffer: 1 << 28,
  }).stdout
    .split('\n')
    .map((l) => l.split(' '));
  const blobIds = new Set(types.filter(([, t]) => t === 'blob').map(([id]) => id));
  let total = 0;
  const seen = new Set();
  for (const [id, path] of objs) {
    if (!blobIds.has(id) || seen.has(id)) continue;
    seen.add(id);
    const nameIssue = scanFileName(path);
    if (nameIssue) total += report(`${path} @${id.slice(0, 8)}`, [{ line: 0, type: nameIssue, sample: '' }]);
    const buf = spawnSync('git', ['cat-file', 'blob', id], { maxBuffer: 1 << 28 }).stdout;
    if (!buf || buf.length > MAX_BYTES || isBinary(buf)) continue;
    total += report(`${path} @${id.slice(0, 8)}`, scanText(buf.toString('utf8'), path));
  }
  return total;
}

function main() {
  const mode = process.argv[2] || '--all';
  let total = 0;
  if (mode === '--staged') {
    const files = git('diff', '--cached', '--name-only', '--diff-filter=ACM').split('\n').filter(Boolean);
    total = scanFiles(files, (f) => execFileSync('git', ['show', `:${f}`], { maxBuffer: 1 << 28 }));
  } else if (mode === '--history') {
    total = scanHistory();
  } else {
    total = scanFiles(git('ls-files').split('\n').filter(Boolean), (f) => readFileSync(f));
  }
  if (total > 0) {
    console.error(`\nsecret-scan: ${total} achado(s) (${mode}). Remova o segredo, troque a credencial e use variável de ambiente.`);
    process.exit(1);
  }
  console.log(`secret-scan: nada encontrado (${mode}).`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
