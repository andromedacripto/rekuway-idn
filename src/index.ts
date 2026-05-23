import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import identityRoutes from './routes/identityRoutes'
import internalRoutes from './routes/internalRoutes';
import verifyIdentityRouter from './routes/verify-identity';
import apiKeyRoutes from './routes/apiKeyRoutes';
import { requireApiKey } from './middleware/auth';
import { startDeadmanMonitor } from './services/defensiveService';
import analyzeRoutes from './routes/analyzeRoutes';

dotenv.config();

const app = express();

// ── Remove fingerprint do Express ─────────────────────────────
app.disable('x-powered-by');

// ── Middleware global de headers ──────────────────────────────
app.use((req: Request, res: Response, next: NextFunction) => {
  res.removeHeader('x-powered-by');
  res.removeHeader('server');
  res.removeHeader('x-vercel-id');
  res.setHeader('server', 'edge');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use(cors());

// ── Rate Limiting Global por IP (Redis) ──────────────────────
import { Redis } from '@upstash/redis'
const _redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
})
const _RL_MAX = 10
const _RL_WIN = 60

app.use(async (req: Request, res: Response, next: NextFunction) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown')
      .toString().split(',')[0].trim()
    const key = `rl:${ip}`
    const count = await _redis.incr(key)
    if (count === 1) await _redis.expire(key, _RL_WIN)
    if (count > _RL_MAX) {
      const excess = count - _RL_MAX
      const penaltyMs = Math.min(excess * 200, 3000)
      await new Promise(r => setTimeout(r, penaltyMs))
      return res.status(200).json({ success: true, status: 'ok', mode: 'stealth' })
    }
    next()
  } catch {
    next()
  }
})

app.use(express.json());

// ── Health check ──────────────────────────────────────────────
app.get('/', (req: Request, res: Response) => {
  res.json({ status: 'ok', ts: Date.now() });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', ts: Date.now() });
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api-keys', apiKeyRoutes);
app.use('/identity', identityRoutes)
app.use('/internal', internalRoutes);
app.use('/analyze', analyzeRoutes);
app.use('/api/verify-identity', requireApiKey, verifyIdentityRouter);

// ── Deadman Monitor ───────────────────────────────────────────
startDeadmanMonitor();

// ── Start server ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] server ready`);
});

// ── Catch-all para métodos não permitidos ─────────────────────
app.use((req: Request, res: Response) => {
  res.status(200).json({ success: true, status: 'ok', mode: 'stealth' })
})

export default app;
