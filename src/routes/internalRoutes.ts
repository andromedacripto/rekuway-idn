import { Router, Request, Response } from 'express';
import { db } from '../config/database';
import { runDeadmanSweep } from '../services/defensiveService';
import { clearSession } from '../services/sessionGuard';
import { safeEqualSecret, validateInternalSecret } from '../utils/internalSecret';

const router = Router();

router.get('/stats', async (req: Request, res: Response) => {
  try {
    // Fail-closed: sem INTERNAL_SECRET configurado, toda requisição é recusada.
    const secret = req.headers['x-internal-secret'];
    if (!validateInternalSecret(secret)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const identityKeys = await db.keys('identity:*');

    let activeCount = 0;
    let deadmanCount = 0;

    for (const key of identityKeys) {
      const identity = await db.getIdentity(key.replace('identity:', ''));
      if (identity && identity.isAlive) {
        activeCount++;
        if (identity.paranoiaLevel === 'deadman') deadmanCount++;
      }
    }

    return res.json({
      activeIdentities: activeCount,
      totalInRedis: identityKeys.length,
      deadmanActive: deadmanCount,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('Stats error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

/**
 * Varredura do deadman para ambientes serverless (onde setInterval não é
 * confiável). Aceita x-internal-secret ou `Authorization: Bearer <CRON_SECRET>`
 * (formato que o Vercel Cron envia). Sem nenhum segredo configurado, recusa.
 */
router.all('/deadman-sweep', async (req: Request, res: Response) => {
  const bearer = (req.headers.authorization || '').replace(/^Bearer /, '');
  const allowed =
    validateInternalSecret(req.headers['x-internal-secret']) ||
    safeEqualSecret(bearer, process.env.CRON_SECRET);
  if (!allowed) return res.status(401).json({ error: 'Unauthorized' });

  try {
    return res.json(await runDeadmanSweep());
  } catch (error) {
    console.error('Deadman sweep error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

/**
 * Suporte: libera uma sessão travada ou bloqueada (ex.: dono legítimo que
 * perdeu o autenticador). Só quem tem INTERNAL_SECRET (o dashboard) chama.
 */
router.post('/identities/:id/unlock', async (req: Request, res: Response) => {
  if (!validateInternalSecret(req.headers['x-internal-secret'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = req.params.id;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ error: 'Invalid id' });
  try {
    await clearSession(id);
    for (const prefix of ['ips', 'fingerprint', 'geo']) {
      await db.delete(`${prefix}:${id}`);
    }
    return res.json({ success: true });
  } catch (error) {
    console.error('Unlock error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
