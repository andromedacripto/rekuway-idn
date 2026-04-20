import { Router, Request, Response } from 'express'
import { db } from '../config/database'

const router = Router()

router.get('/stats', async (req: Request, res: Response) => {
  try {
    const secret = req.headers['x-internal-secret']
    if (secret !== process.env.INTERNAL_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const identityKeys = await db.keys('identity:*')
    
    let activeCount = 0
    let deadmanCount = 0
    
    for (const key of identityKeys) {
      const identity = await db.getIdentity(key.replace('identity:', ''))
      if (identity && identity.isAlive) {
        activeCount++
        if (identity.paranoiaLevel === 'deadman') deadmanCount++
      }
    }

    return res.json({
      activeIdentities: activeCount,
      totalInRedis: identityKeys.length,
      deadmanActive: deadmanCount,
      timestamp: Date.now()
    })
  } catch (error) {
    console.error('Stats error:', error)
    return res.status(500).json({ error: 'Internal error' })
  }
})

export default router
