import express, { NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const router = express.Router();

// JWT secret from environment (no weak fallback in production)
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev-only-secret' : undefined as any);
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET must be set in production');
}

// Generate a short, human-friendly client_id like "c-4fk7x2"
async function generateShortClientId(): Promise<string> {
  // Try up to 5 times to avoid collisions
  for (let attempt = 0; attempt < 5; attempt++) {
    const rand = crypto.randomBytes(3).toString('hex'); // 6 hex chars
    const candidate = `c-${rand}`;
    const { data: existing, error } = await supabase.from('profiles').select('id').eq('client_id', candidate).maybeSingle();
    if (!existing && !error) return candidate;
  }
  // Fallback to longer if we somehow collide repeatedly
  return `c-${crypto.randomBytes(6).toString('hex')}`;
}

// Diagnostics: check Supabase connectivity and profiles table
router.get('/diagnose', requireAuth, requireAdmin, async (_req, res, next: NextFunction) => {
  try {
    // Try a lightweight select on profiles
    const { count, error } = await supabase
      .from('profiles')
      .select('*', { count: 'exact', head: true });

    res.json({
      success: true,
      data: {
        ok: !error,
        profiles_count: typeof count === 'number' ? count : null
      }
    });
  } catch (e: any) {
    logger.error('Diagnostics failed', e);
    next(e);
  }
});

// Validation schemas
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const googleAuthSchema = z.object({
  token: z.string().optional(),
  code: z.string().optional()
});

const clerkSyncSchema = z.object({
  clerk_user_id: z.string(),
  email: z.string().email(),
  full_name: z.string().optional()
});

// Token settings
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Helper function to generate JWT
function generateToken(userId: string, email: string, clientId?: string): string {
  // Let jsonwebtoken set standard iat (seconds) automatically; shorten expiry
  return jwt.sign({ userId, email, clientId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL });
}

function hashToken(raw: string) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

async function issueTokens(user: { id: string; email: string; client_id?: string }) {
  const access_token = generateToken(user.id, user.email, user.client_id);
  const refresh_token = `rt-${crypto.randomBytes(32).toString('hex')}`;
  const token_hash = hashToken(refresh_token);
  const expires_at = new Date(Date.now() + REFRESH_TOKEN_TTL_MS).toISOString();
  const { error } = await supabase
    .from('refresh_tokens')
    .insert({ user_id: user.id, client_id: user.client_id || null, token_hash, expires_at, revoked: false });
  if (error) logger.error('Supabase insert refresh_token error:', error);
  return { access_token, refresh_token };
}

// Simple auth helper: extract user from Bearer token
async function getUserFromAuthHeader(req: express.Request) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    const { data: user } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', decoded.userId)
      .maybeSingle();
    return user || null;
  } catch {
    return null;
  }
}

async function requireAuth(req: express.Request, res: express.Response, next: NextFunction) {
  const user = await getUserFromAuthHeader(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  (req as any).user = user;
  next();
}

function requireAdmin(req: express.Request, res: express.Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Helper function to find or create user profile
async function findOrCreateUser(email: string, name: string, organizationId?: string) {
  try {
    // Check if user exists
    const { data: existingUser, error: findErr } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (findErr) {
      logger.error('Supabase find user error:', findErr);
    }

    if (existingUser) {
      // Ensure client_id exists
      if (!existingUser.client_id) {
        const clientId = await generateShortClientId();
        const { error: updErr } = await supabase.from('profiles').update({ client_id: clientId }).eq('id', existingUser.id);
        if (updErr) logger.error('Supabase update client_id error:', updErr);
        return { ...existingUser, client_id: clientId };
      }
      return existingUser;
    }

    // Create new user with a fresh short client_id
    const clientId = await generateShortClientId();
    const { data: newUser, error: createError } = await supabase
      .from('profiles')
      .insert({
        email,
        full_name: name,
        organization_id: organizationId || null,
        role: 'user',
        client_id: clientId
      })
      .select()
      .single();

    if (createError) {
      logger.error('Supabase create profile error:', createError);
      throw createError;
    }

    return newUser;
  } catch (error) {
    logger.error('Error finding/creating user:', error);
    throw error;
  }
}

// POST /api/auth/clerk/sync - called from frontend after Clerk sign-in
router.post('/clerk/sync', async (req, res, next: NextFunction) => {
  try {
    // In production, require an internal secret for this route to prevent spoofing of clerk_user_id
    if (process.env.NODE_ENV === 'production') {
      const provided = req.headers['x-internal-auth'];
      const required = process.env.CLERK_SYNC_SECRET;
      if (!required || provided !== required) {
        const err: any = new Error('Forbidden');
        err.statusCode = 403;
        throw err;
      }
    }
    const { clerk_user_id, email, full_name } = clerkSyncSchema.parse(req.body);

    // Try existing by clerk_user_id first
    let { data: user, error: byClerkErr } = await supabase
      .from('profiles')
      .select('*')
      .eq('clerk_user_id', clerk_user_id)
      .maybeSingle();

    if (byClerkErr) logger.error('Supabase select by clerk_user_id error:', byClerkErr);

    if (!user) {
      // Fallback by email
      const { data: byEmail, error: byEmailErr } = await supabase
        .from('profiles')
        .select('*')
        .eq('email', email)
        .maybeSingle();

      if (byEmailErr) logger.error('Supabase select by email error:', byEmailErr);

      if (byEmail) {
        // Attach clerk id and ensure client_id exists
        const clientId = byEmail.client_id || await generateShortClientId();
        const { data: updated, error: updErr } = await supabase
          .from('profiles')
          .update({ clerk_user_id, client_id: clientId, full_name: full_name || byEmail.full_name })
          .eq('id', byEmail.id)
          .select('*')
          .single();
        if (updErr) logger.error('Supabase update profile error:', updErr);
        user = updated!;
      } else {
        // Create new profile with fresh client_id
        const clientId = await generateShortClientId();
        const { data: created, error: insErr } = await supabase
          .from('profiles')
          .insert({ email, full_name: full_name || email.split('@')[0], role: 'user', client_id: clientId, clerk_user_id })
          .select('*')
          .single();
        if (insErr) {
          logger.error('Supabase insert profile error:', insErr);
          throw insErr;
        }
        user = created!;
      }
    }

    // Ensure a dashboard API key exists; avoid auto-rotation
    let dashboard_key: string | null = null;
    const { data: existingKey, error: keySelErr } = await supabase
      .from('api_keys')
      .select('*')
      .eq('client_id', user.client_id)
      .maybeSingle();
    if (keySelErr) logger.error('Supabase select api_key error:', keySelErr);

    if (!existingKey) {
      const rawKey = `sk-${crypto.randomBytes(32).toString('hex')}`;
      const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
      const { error: insKeyErr } = await supabase
        .from('api_keys')
        .insert({
          client_id: user.client_id,
          key_hash: keyHash,
          client_name: `${user.full_name || 'User'} Dashboard`,
          permissions: JSON.stringify(["read","write","sdk"]),
          rate_limit_per_minute: 600,
          is_active: true,
          verified: true,
          verified_at: new Date().toISOString()
        });
      if (insKeyErr) logger.error('Supabase insert api_key error:', insKeyErr);
      else dashboard_key = rawKey;
    }

    // Issue access + refresh tokens for dashboard session
    const { access_token, refresh_token } = await issueTokens({ id: user.id, email: user.email, client_id: user.client_id });

    res.json({ success: true, data: { client_id: user.client_id, user_id: user.id, email: user.email, dashboard_key, access_token, refresh_token } });
  } catch (error: any) {
    logger.error('Clerk sync failed:', error);
    next(error);
  }
});

// POST /api/auth/login - Email/password login
router.post('/login', async (req, res, next: NextFunction) => {
  try {
    if (process.env.NODE_ENV === 'production') {
      return res.status(404).json({ error: 'Not available' });
    }
    const { email, password } = loginSchema.parse(req.body);

    // Demo: accept any email/password
    const user = await findOrCreateUser(email, email.split('@')[0] || 'User');

    const { access_token, refresh_token } = await issueTokens({ id: user.id, email: user.email, client_id: user.client_id });

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        organization_id: user.organization_id,
        client_id: user.client_id
      },
      token: access_token,
      access_token,
      refresh_token
    });

    logger.info(`User logged in: ${email}`);
  } catch (error) {
    logger.error('Login failed:', error);
    next(error as any);
  }
});

// POST /api/auth/google - Google OAuth login
router.post('/google', async (req, res, next: NextFunction) => {
  try {
    if (process.env.NODE_ENV === 'production') {
      return res.status(404).json({ error: 'Not available' });
    }
    const { token, code } = googleAuthSchema.parse(req.body);

    // Simulate Google auth success
    const demoEmail = 'user@gmail.com';
    const demoName = 'Google User';
    
    const user = await findOrCreateUser(demoEmail, demoName);

    const { access_token, refresh_token } = await issueTokens({ id: user.id, email: user.email, client_id: user.client_id });

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        organization_id: user.organization_id,
        client_id: user.client_id
      },
      token: access_token,
      access_token,
      refresh_token
    });

    logger.info(`Google user logged in: ${demoEmail}`);
  } catch (error) {
    logger.error('Google auth failed:', error);
    next(error as any);
  }
});

// POST /api/auth/logout - Logout
router.post('/logout', requireAuth, async (req, res, next: NextFunction) => {
  try {
    const caller = (req as any).user;
    const refreshToken = req.body?.refresh_token as string | undefined;
    if (refreshToken) {
      const token_hash = hashToken(refreshToken);
      const { error } = await supabase
        .from('refresh_tokens')
        .update({ revoked: true })
        .eq('token_hash', token_hash)
        .eq('user_id', caller.id);
      if (error) logger.error('Supabase revoke refresh_token error:', error);
    } else {
      const { error } = await supabase
        .from('refresh_tokens')
        .update({ revoked: true })
        .eq('user_id', caller.id);
      if (error) logger.error('Supabase revoke all refresh_tokens error:', error);
    }

    res.json({ success: true, message: 'Logged out successfully' });
    logger.info(`User logged out user_id=${caller.id}`);
  } catch (error) {
    logger.error('Logout failed:', error);
    next(error as any);
  }
});

// GET /api/auth/me - Get current user info
router.get('/me', async (req, res, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    const { data: user, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      const e: any = new Error('Invalid token');
      e.name = 'UnauthorizedError';
      e.statusCode = 401;
      return next(e);
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        organization_id: user.organization_id,
        client_id: user.client_id
      }
    });
  } catch (error) {
    logger.error('Token verification failed:', error);
    const e: any = new Error('Invalid token');
    e.name = 'UnauthorizedError';
    e.statusCode = 401;
    next(e);
  }
});

// POST /api/auth/test-connection - Verify API key validity
router.post('/test-connection', async (req, res, next: NextFunction) => {
  try {
    const apiKey = (req.body && req.body.api_key) || req.headers['x-api-key'];
    if (!apiKey || typeof apiKey !== 'string') {
      return res.status(400).json({ success: false, error: 'api_key required' });
    }
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const { data: keyRec, error } = await supabase
      .from('api_keys')
      .select('*')
      .eq('key_hash', keyHash)
      .eq('is_active', true)
      .maybeSingle();
    if (error) logger.error('Supabase select api_keys error:', error);
    if (!keyRec) {
      return res.status(401).json({ success: false, error: 'Invalid API key' });
    }
    return res.json({ success: true, data: { client_id: keyRec.client_id, permissions: keyRec.permissions } });
  } catch (error) {
    logger.error('Test connection failed:', error);
    next(error as any);
  }
});

export { router as authRoutes };

// POST /api/auth/rotate-key - Rotate API key on explicit user/admin request
router.post('/rotate-key', requireAuth, async (req, res, next: NextFunction) => {
  try {
    const caller = (req as any).user;
    const requestedClientId = req.body?.client_id as string | undefined;
    const targetClientId = caller.role === 'admin' && requestedClientId ? requestedClientId : caller.client_id;
    if (!targetClientId) {
      return res.status(400).json({ success: false, error: 'client_id not resolved' });
    }

    // Read existing to preserve settings
    const { data: existingKey, error: selErr } = await supabase
      .from('api_keys')
      .select('*')
      .eq('client_id', targetClientId)
      .maybeSingle();
    if (selErr) logger.error('Supabase select api_keys error:', selErr);

    const rawKey = `sk-${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const payload: any = {
      client_id: targetClientId,
      key_hash: keyHash,
      client_name: existingKey?.client_name || `${caller.full_name || 'User'} Dashboard`,
      permissions: existingKey?.permissions || JSON.stringify(["read","write","sdk"]),
      rate_limit_per_minute: existingKey?.rate_limit_per_minute ?? 600,
      is_active: true,
      verified: true,
      verified_at: new Date().toISOString()
    };

    const { error: upsertErr } = await supabase
      .from('api_keys')
      .upsert(payload, { onConflict: 'client_id' });
    if (upsertErr) {
      logger.error('Supabase upsert api_keys error:', upsertErr);
      return res.status(500).json({ success: false, error: 'Failed to rotate key' });
    }

    logger.info(`API key rotated for client_id=${targetClientId} by user_id=${caller.id}`);
    return res.json({ success: true, data: { client_id: targetClientId, dashboard_key: rawKey } });
  } catch (error) {
    logger.error('Rotate key failed:', error);
    next(error as any);
  }
});

// POST /api/auth/refresh - Exchange refresh token for new tokens (rotate refresh token)
router.post('/refresh', async (req, res, next: NextFunction) => {
  try {
    const refreshToken = req.body?.refresh_token as string | undefined;
    if (!refreshToken || typeof refreshToken !== 'string') {
      return res.status(400).json({ error: 'refresh_token required' });
    }
    const nowIso = new Date().toISOString();
    const token_hash = hashToken(refreshToken);
    const { data: stored, error } = await supabase
      .from('refresh_tokens')
      .select('*')
      .eq('token_hash', token_hash)
      .eq('revoked', false)
      .gt('expires_at', nowIso)
      .maybeSingle();
    if (error) logger.error('Supabase select refresh_token error:', error);
    if (!stored) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Load user
    const { data: user, error: userErr } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', stored.user_id)
      .maybeSingle();
    if (userErr || !user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Rotate refresh token in place
    const new_refresh_token = `rt-${crypto.randomBytes(32).toString('hex')}`;
    const new_hash = hashToken(new_refresh_token);
    const new_expiry = new Date(Date.now() + REFRESH_TOKEN_TTL_MS).toISOString();
    const { error: updErr } = await supabase
      .from('refresh_tokens')
      .update({ token_hash: new_hash, expires_at: new_expiry })
      .eq('token_hash', token_hash);
    if (updErr) logger.error('Supabase update refresh_token error:', updErr);

    const access_token = generateToken(user.id, user.email, user.client_id);
    return res.json({ success: true, access_token, refresh_token: new_refresh_token });
  } catch (error) {
    logger.error('Refresh token exchange failed:', error);
    next(error as any);
  }
});
