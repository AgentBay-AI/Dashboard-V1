import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';

export interface AuthenticatedRequest extends Request {
    clientId?: string;
    clientPermissions?: string[];
    rateLimitPerMinute?: number;
    traceId?: string;
    spanId?: string;
    traceContext?: any;
}

export async function authenticateApiKey(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const authHeader = req.headers.authorization;
        
        // Debug: Log auth header
        logger.debug('Auth header:', { authHeader });

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            logger.warn('Missing or invalid Authorization header');
            res.status(401).json({ error: 'Unauthorized', message: 'Missing or invalid Authorization header' });
            return;
        }

        const apiKey = authHeader.split(' ')[1];
        
        // Debug: Log API key (in development only)
        if (process.env.NODE_ENV === 'development') {
            logger.debug('Received API key:', { apiKey });
        }

        // Hash the API key
        const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
        
        // Debug: Log hashed key
        logger.debug('Hashed key:', { hashedKey });

        // Query the database for the API key
        const { data: apiKeyData, error } = await supabase
            .from('api_keys')
            .select('*')
            .eq('key_hash', hashedKey)
            .eq('is_active', true)
            .single();

        // Debug: Log database query result
        logger.debug('API key lookup result:', { 
            found: !!apiKeyData,
            error: error?.message,
            clientId: apiKeyData?.client_id,
            permissions: apiKeyData?.permissions
        });

        if (error || !apiKeyData) {
            logger.warn('Invalid API key attempt', {
                hashedKey,
                ip: req.ip,
                userAgent: req.headers['user-agent']
            });
            res.status(401).json({ error: 'Invalid API key', message: 'The provided API key is invalid or inactive' });
            return;
        }

        // Attach client info to request
        req.clientId = apiKeyData.client_id;
        req.rateLimitPerMinute = apiKeyData.rate_limit_per_minute;

        // Parse permissions
        try {
            req.clientPermissions = Array.isArray(apiKeyData.permissions)
                ? apiKeyData.permissions
                : JSON.parse(apiKeyData.permissions || '["read", "write"]');
            
            // Debug: Log parsed permissions
            logger.debug('Parsed permissions:', {
                raw: apiKeyData.permissions,
                parsed: req.clientPermissions
            });
        } catch (error) {
            logger.error('Failed to parse permissions:', {
                error,
                permissions: apiKeyData.permissions
            });
            req.clientPermissions = ['read', 'write'];
        }

        // Debug: Log final request state
        logger.debug('Request authenticated:', {
            clientId: req.clientId,
            permissions: req.clientPermissions,
            rateLimit: req.rateLimitPerMinute
        });

        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        res.status(500).json({ error: 'Internal server error', message: 'An error occurred during authentication' });
    }
}

export function requirePermission(permission: string) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): any => {
        // Debug: Log permission check
        logger.debug('Checking permission:', {
            required: permission,
            clientPermissions: req.clientPermissions,
            clientId: req.clientId
        });

        if (!req.clientPermissions?.includes(permission)) {
            logger.warn('Permission denied:', {
                required: permission,
                clientPermissions: req.clientPermissions,
                clientId: req.clientId
            });
            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `This operation requires '${permission}' permission`
            });
        }
        next();
    };
} 