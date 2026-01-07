import { Router, Request, Response } from 'express';
import { createApiKey, listUserApiKeys, revokeApiKey } from '../services/apiKeyService';

const router = Router();

/**
 * POST /api-keys
 * 
 * Cria uma nova API key
 * 
 * Body:
 * {
 *   "userId": "user_123",
 *   "name": "Production API",
 *   "tier": "startup"
 * }
 * 
 * ⚠️ Em produção, userId deve vir de autenticação (JWT/OAuth)
 * Por enquanto é manual pra testes
 */
router.post('/', async (req: Request, res: Response) => {
  try {
    const { userId, name, tier = 'hobby' } = req.body;
    
    if (!userId || !name) {
      return res.status(400).json({
        success: false,
        error: 'userId and name are required'
      });
    }
    
    if (!['hobby', 'startup', 'business', 'enterprise'].includes(tier)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid tier. Must be: hobby, startup, business, or enterprise'
      });
    }
    
    const { apiKey, plainKey } = await createApiKey(userId, name, tier);
    
    res.status(201).json({
      success: true,
      message: '⚠️ SAVE YOUR API KEY! It will never be shown again.',
      apiKey: {
        key: plainKey, // Única vez que mostra a key completa
        name: apiKey.name,
        tier: apiKey.tier,
        limits: {
          identitiesPerMonth: apiKey.rateLimit.identitiesPerMonth,
          requestsPerMinute: apiKey.rateLimit.requestsPerMinute
        },
        createdAt: apiKey.createdAt
      },
      docs: 'https://rekuway.com/docs/authentication'
    });
    
  } catch (error) {
    console.error('[API_KEYS] Error creating API key:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create API key'
    });
  }
});

/**
 * GET /api-keys/:userId
 * 
 * Lista todas as API keys de um usuário
 * 
 * ⚠️ Em produção, userId deve ser verificado com autenticação
 */
router.get('/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    
    const apiKeys = await listUserApiKeys(userId);
    
    // Remove informações sensíveis
    const safeKeys = apiKeys.map(key => ({
      key: key.key, // Já vem mascarado (rkwy_live_abc......)
      name: key.name,
      tier: key.tier,
      limits: key.rateLimit,
      usage: {
        identitiesCreated: key.usage.identitiesCreated,
        requestsThisMinute: key.usage.requestsThisMinute
      },
      isActive: key.isActive,
      createdAt: key.createdAt
    }));
    
    res.json({
      success: true,
      apiKeys: safeKeys,
      total: safeKeys.length
    });
    
  } catch (error) {
    console.error('[API_KEYS] Error listing API keys:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to list API keys'
    });
  }
});

/**
 * DELETE /api-keys/:hashedKey
 * 
 * Revoga (desativa) uma API key
 * 
 * ⚠️ Em produção, verificar se o usuário é dono da key
 */
router.delete('/:hashedKey', async (req: Request, res: Response) => {
  try {
    const { hashedKey } = req.params;
    
    const revoked = await revokeApiKey(hashedKey);
    
    if (!revoked) {
      return res.status(404).json({
        success: false,
        error: 'API key not found'
      });
    }
    
    res.json({
      success: true,
      message: 'API key revoked successfully'
    });
    
  } catch (error) {
    console.error('[API_KEYS] Error revoking API key:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke API key'
    });
  }
});

export default router;