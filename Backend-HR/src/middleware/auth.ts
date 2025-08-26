import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';

export interface AuthenticatedRequest extends Request {
  clientId?: string;
  permissions?: string[];
  apiKeyId?: string;
}

export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;
    if (!authReq.permissions || !authReq.permissions.includes(permission)) {
      return res.status(403).json({ error: 'Forbidden: missing permission' });
    }
    next();
  };
}

export async function authenticateApiKey(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers['authorization'];
    const headerName = process.env.SDK_AUTH_HEADER_NAME || 'authorization';
    const rawAuth = headerName.toLowerCase() === 'authorization' ? (Array.isArray(authHeader) ? authHeader[0] : authHeader) : (req.headers[headerName.toLowerCase()] as string | undefined);

    if (!rawAuth) {
      return res.status(401).json({ error: 'Missing authorization' });
    }

    let rawKey = rawAuth;
    if (rawKey.startsWith('Bearer ')) rawKey = rawKey.slice(7);

    const hashedKey = crypto.createHash('sha256').update(rawKey).digest('hex');

    const { data: keyRow, error } = await supabase
      .from('api_keys')
      .select('*')
      .eq('key_hash', hashedKey)
      .eq('is_active', true)
      .maybeSingle();

    if (error || !keyRow) {
      logger.warn('Invalid API key attempt:', { error: error?.message, hashedKey: hashedKey.slice(0, 8) + '...' });
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Update last_used_at and usage_count
    try {
      await supabase
        .from('api_keys')
        .update({ last_used_at: new Date().toISOString(), usage_count: (keyRow.usage_count || 0) + 1 })
        .eq('id', keyRow.id);
    } catch (e) {
      logger.warn('Failed to update key usage stats', { id: keyRow.id, error: String(e) });
    }

    const authReq = req as AuthenticatedRequest;
    authReq.clientId = keyRow.client_id;
    try {
      const perms = Array.isArray(keyRow.permissions) ? keyRow.permissions : JSON.parse(keyRow.permissions || '[]');
      authReq.permissions = perms;
    } catch {
      authReq.permissions = [];
    }
    authReq.apiKeyId = keyRow.id;

    // Optional override of client id for SDK testing (non-production only)
    if (process.env.NODE_ENV !== 'production') {
      const overrideClientId = (req.headers['x-client-id'] as string | undefined)?.trim();
      if (overrideClientId) {
        authReq.clientId = overrideClientId;
      }
    }

    next();
  } catch (e: any) {
    logger.error('authenticateApiKey failed', e);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Provide a combined dashboard-or-api-key middleware to satisfy existing imports
export function authenticateDashboardOrApiKey(req: Request, res: Response, next: NextFunction) {
  return authenticateApiKey(req, res, next);
} 