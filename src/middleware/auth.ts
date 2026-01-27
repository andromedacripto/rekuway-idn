import { Request, Response, NextFunction } from 'express';
import { validateApiKey, checkRateLimit, ApiKey } from '../services/apiKeyService';

// Extende Request pra incluir apiKey
declare global {
  namespace Express {
    interface Request {
      apiKey?: ApiKey;
    }
  }
}

/**
 * Middleware que valida API key em todos os endpoints protegidos
 * 
 * Header esperado: Authorization: Bearer rkwy_live_xxxxx
 * Ou query param: ?apiKey=rkwy_live_xxxxx
 */
export async function requireApiKey(req: Request, res: Response, next: NextFunction) {
  try {
    // Pega API key do header ou query
    const authHeader = req.headers.authorization;
    const queryApiKey = req.query.apiKey as string;
    
    let apiKeyString: string | null = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      apiKeyString = authHeader.substring(7);
    } else if (queryApiKey) {
      apiKeyString = queryApiKey;
    }
    
    if (!apiKeyString) {
      return res.status(401).json({
        success: false,
        error: 'API key required',
        message: 'Provide API key in Authorization header (Bearer token) or apiKey query parameter',
        docs: 'https://rekuway.com/docs/authentication'
      });
    }
    
    // Valida API key
    const apiKey = await validateApiKey(apiKeyString);
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        error: 'Invalid API key',
        message: 'API key is invalid or has been revoked',
        docs: 'https://rekuway.com/docs/authentication'
      });
    }
    
    // Verifica rate limit (não é criação de identidade)
    const rateLimitCheck = await checkRateLimit(apiKey, false);
    
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
        message: rateLimitCheck.reason,
        limits: rateLimitCheck.limits,
        docs: 'https://rekuway.com/docs/rate-limits'
      });
    }
    
    // Adiciona apiKey ao request pra uso posterior
    req.apiKey = apiKey;
    
    // Adiciona headers de rate limit na resposta
    res.setHeader('X-RateLimit-Limit', apiKey.rateLimit.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Remaining', rateLimitCheck.limits.requestsPerMinute.toString());
    res.setHeader('X-RateLimit-Reset', new Date(apiKey.usage.lastRequest + 60000).toISOString());
    
    next();
    
  } catch (error) {
    console.error('[AUTH] Error validating API key:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication error',
      message: 'Failed to validate API key'
    });
  }
}

/**
 * Middleware específico para criação de identidades
 * Verifica limite mensal de identidades
 */
export async function checkIdentityCreationLimit(req: Request, res: Response, next: NextFunction) {
  try {
    const apiKey = req.apiKey;
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        error: 'API key required'
      });
    }
    
    // Verifica se pode criar identidade (checa limite mensal)
    const rateLimitCheck = await checkRateLimit(apiKey, true);
    
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: 'Monthly identity limit exceeded',
        message: rateLimitCheck.reason,
        limits: rateLimitCheck.limits,
        upgrade: 'https://rekuway.com/pricing'
      });
    }
    
    // Adiciona headers de limites
    res.setHeader('X-Identities-Limit', apiKey.rateLimit.identitiesPerMonth.toString());
    res.setHeader('X-Identities-Remaining', rateLimitCheck.limits.identitiesRemaining.toString());
    res.setHeader('X-Identities-Reset', new Date(apiKey.usage.resetDate).toISOString());
    
    next();
    
  } catch (error) {
    console.error('[AUTH] Error checking identity limit:', error);
    res.status(500).json({
      success: false,
      error: 'Rate limit check failed'
    });
  }
}