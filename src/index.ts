import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import identityRoutes from './routes/identityRoutes';
import verifyIdentityRouter from './routes/verify-identity';
import apiKeyRoutes from './routes/apiKeyRoutes';
import { requireApiKey } from './middleware/auth';
import { startDeadmanMonitor } from './services/defensiveService';
import crypto from 'crypto';

dotenv.config();

const app = express();

// ── Remove fingerprint do Express ─────────────────────────────
app.disable('x-powered-by');

// ── Middleware global de headers ──────────────────────────────
// Sobrescreve headers que revelam stack/infra real
app.use((req, res, next) => {
  res.removeHeader('x-powered-by');
  res.removeHeader('server');
  res.removeHeader('x-vercel-id');
  res.setHeader('server', 'edge');
  next();
});

app.use(cors());

// ── Rate Limiting Global por IP ───────────────────────────────
const _rlMap = new Map<string, { count: number; resetAt: number }>()
const _RL_MAX = 10
const _RL_WIN = 60_000

app.use((req: any, res: any, next: any) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown')
    .toString().split(',')[0].trim()
  const now = Date.now()
  const entry = _rlMap.get(ip)
  if (!entry || now > entry.resetAt) {
    _rlMap.set(ip, { count: 1, resetAt: now + _RL_WIN })
    return next()
  }
  if (entry.count >= _RL_MAX) {
    return res.status(429).json({ success: false, error: 'Too many requests' })
  }
  entry.count++
  next()
})

app.use(express.json());

// ── Health check — sem informação útil ───────────────────────
// Retorna apenas o suficiente pra load balancer considerar healthy
// Sem uptime, sem versão, sem nome do sistema
app.get('/', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api-keys', apiKeyRoutes);
app.use('/identity', identityRoutes);
app.use('/api/verify-identity', requireApiKey, verifyIdentityRouter);

// ── Deadman Monitor ───────────────────────────────────────────
startDeadmanMonitor();

// ── Start server (não roda na Vercel) ─────────────────────────
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    // sem log de porta ou nome — só confirma que subiu
    console.log(`[${new Date().toISOString()}] server ready`);
  });
}

export default app;
