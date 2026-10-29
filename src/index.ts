import dotenv from 'dotenv';
dotenv.config();

import app from './app';
import { startDeadmanMonitor } from './services/defensiveService';

// ── Deadman Monitor ───────────────────────────────────────────
// Em serverless (Vercel) setInterval não é confiável: lá, a varredura vem de
// um cron chamando GET /internal/deadman-sweep, e /identity/check também
// aplica o prazo na hora.
if (!process.env.VERCEL) {
  startDeadmanMonitor();
}

// ── Start server ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] server ready`);
});

export default app;
