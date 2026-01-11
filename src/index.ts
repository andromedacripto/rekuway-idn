import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import identityRoutes from './routes/identityRoutes';
import apiKeyRoutes from './routes/apiKeyRoutes';
import { securityLogger, rateLimitByIP } from './middleware/securityLogger';
import { startDeadmanMonitor } from './services/heartbeat';

const app = express();

app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(securityLogger);
app.use(rateLimitByIP);

app.get('/', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Rekuway IDN API is running ✅',
    version: '1.0.0-MVP',
    features: [
      'Hybrid Defense (ALLOW → REGENERATE → LIE → KILL)',
      'Deadman Switch with Heartbeat Monitor 💓',
      '4 Paranoia Levels',
      'Fake Metadata Deception'
    ]
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Rekuway IDN',
    version: '1.0.0-MVP',
    timestamp: new Date().toISOString(),
    redis: process.env.UPSTASH_REDIS_REST_URL ? 'connected' : 'not configured',
    deadmanMonitor: 'active'
  });
});

app.use('/identity', identityRoutes);
app.use('/api-keys', apiKeyRoutes);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.path
  });
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

console.log('[SERVER] 🚀 Starting...');
startDeadmanMonitor();

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`[SERVER] 🚀 Running on port ${PORT}`);
    console.log(`[SERVER] 💓 Deadman monitor active`);
  });
}

export default app;
