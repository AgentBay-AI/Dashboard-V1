import { Request, Response, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import crypto from 'crypto';

export interface AuthenticatedRequest extends Request {
  clientId?: string;
  clientPermissions?: string[];
  rateLimitPerMinute?: number;
}

// Rate limiting storage (in production, use Redis)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

export async function authenticateApiKey(
  req: AuthenticatedRequest, 
  res: Response, 
  next: NextFunction
): Promise<any> {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Bearer token must be provided in Authorization header'
      });
    }

    const apiKey = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    if (!apiKey) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'API key cannot be empty'
      });
    }

    // Hash the API key to match stored hash
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    // Validate API key in database
    const { data: apiKeyData, error } = await supabase
      .from('api_keys')
      .select('*')
      .eq('key_hash', keyHash)
      .eq('is_active', true)
      .single();

    if (error || !apiKeyData) {
      logger.warn('Invalid API key attempt', { 
        ip: req.ip, 
        userAgent: req.get('User-Agent'),
        hashedKey: keyHash.substring(0, 8) + '...' // Log partial hash for debugging
      });
      
      return res.status(401).json({
        error: 'Invalid API key',
        message: 'The provided API key is invalid or inactive'
      });
    }

    // Check if API key has expired
    if (apiKeyData.expires_at && new Date(apiKeyData.expires_at) < new Date()) {
      return res.status(401).json({
        error: 'API key expired',
        message: 'The provided API key has expired'
      });
    }

    // Check rate limiting
    const rateLimitResult = await checkRateLimit(apiKeyData.client_id, apiKeyData.rate_limit_per_minute);
    if (!rateLimitResult.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: `Rate limit of ${apiKeyData.rate_limit_per_minute} requests per minute exceeded`,
        retryAfter: Math.ceil(rateLimitResult.resetTime - Date.now() / 1000)
      });
    }

    // Update last used timestamp
    await supabase
      .from('api_keys')
      .update({ last_used_at: new Date().toISOString() })
      .eq('key_hash', keyHash);

    // Attach client info to request
    req.clientId = apiKeyData.client_id;
    req.clientPermissions = Array.isArray(apiKeyData.permissions) 
      ? apiKeyData.permissions 
      : JSON.parse(apiKeyData.permissions || '["read", "write"]');
    req.rateLimitPerMinute = apiKeyData.rate_limit_per_minute;

    logger.info('API key authenticated successfully', {
      clientId: apiKeyData.client_id,
      clientName: apiKeyData.client_name,
      ip: req.ip
    });

    next();
  } catch (error: any) {
    logger.error('Authentication error:', error);
    return res.status(500).json({
      error: 'Authentication service error',
      message: 'Internal server error during authentication'
    });
  }
}

export function requirePermission(permission: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): any => {
    if (!req.clientPermissions?.includes(permission)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `This operation requires '${permission}' permission`
      });
    }
    next();
  };
}

async function checkRateLimit(clientId: string, limitPerMinute: number): Promise<{
  allowed: boolean;
  resetTime: number;
}> {
  const now = Date.now();
  const windowStart = Math.floor(now / 60000) * 60000; // Start of current minute
  const resetTime = windowStart + 60000; // End of current minute
  
  const key = `${clientId}:${windowStart}`;
  const current = rateLimitStore.get(key) || { count: 0, resetTime };
  
  // Clean up old entries
  for (const [storedKey, data] of rateLimitStore.entries()) {
    if (data.resetTime < now) {
      rateLimitStore.delete(storedKey);
    }
  }
  
  if (current.count >= limitPerMinute) {
    return { allowed: false, resetTime: resetTime / 1000 };
  }
  
  current.count++;
  rateLimitStore.set(key, current);
  
  return { allowed: true, resetTime: resetTime / 1000 };
}

// Utility function to generate API keys
export function generateApiKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Utility function to hash API keys
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

// Middleware to validate request payload schemas
export function validateSchema(schema: any) {
  return (req: Request, res: Response, next: NextFunction): any => {
    try {
      const result = schema.parse(req.body);
      req.body = result; // Use validated data
      next();
    } catch (error: any) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'Request body validation failed',
        details: error.errors || error.message
      });
    }
  };
} 