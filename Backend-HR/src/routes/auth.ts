import express, { NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const router = express.Router();

// JWT secret from environment
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

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
router.get('/diagnose', async (_req, res, next: NextFunction) => {
  try {
    // Check envs presence
    const urlSet = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL);
    const keySet = Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY);

    // Try a lightweight select on profiles
    const { count, error } = await supabase
      .from('profiles')
      .select('*', { count: 'exact', head: true });

    res.json({
      success: true,
      data: {
        supabase_env: { urlSet, keySet },
        profiles_count_known: typeof count === 'number',
        profiles_count: count ?? null,
        error: error ? { message: error.message, details: (error as any).details, code: (error as any).code } : null
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

// Helper function to generate JWT
function generateToken(userId: string, email: string, clientId?: string): string {
  return jwt.sign(
    { userId, email, clientId, iat: Date.now() },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
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

    // Always mint a fresh dashboard API key and return it
    const rawKey = `sk-${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const { error: upsertErr } = await supabase
      .from('api_keys')
      .upsert({
        client_id: user.client_id,
        key_hash: keyHash,
        client_name: `${user.full_name || 'User'} Dashboard`,
        permissions: JSON.stringify(["read","write","sdk","admin"]),
        rate_limit_per_minute: 3000,
        is_active: true,
        verified: true,
        verified_at: new Date().toISOString()
      }, { onConflict: 'client_id' });
    if (upsertErr) logger.error('Supabase upsert api_key error:', upsertErr);

    res.json({ success: true, data: { client_id: user.client_id, user_id: user.id, email: user.email, dashboard_key: rawKey } });
  } catch (error: any) {
    logger.error('Clerk sync failed:', error);
    next(error);
  }
});

// POST /api/auth/login - Email/password login
router.post('/login', async (req, res, next: NextFunction) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    // Demo: accept any email/password
    const user = await findOrCreateUser(email, email.split('@')[0] || 'User');

    const token = generateToken(user.id, user.email, user.client_id);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        organization_id: user.organization_id,
        client_id: user.client_id
      },
      token
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
    const { token, code } = googleAuthSchema.parse(req.body);

    // Simulate Google auth success
    const demoEmail = 'user@gmail.com';
    const demoName = 'Google User';
    
    const user = await findOrCreateUser(demoEmail, demoName);

    const authToken = generateToken(user.id, user.email, user.client_id);

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        organization_id: user.organization_id,
        client_id: user.client_id
      },
      token: authToken
    });

    logger.info(`Google user logged in: ${demoEmail}`);
  } catch (error) {
    logger.error('Google auth failed:', error);
    next(error as any);
  }
});

// POST /api/auth/logout - Logout
router.post('/logout', async (req, res, next: NextFunction) => {
  try {
    res.json({ success: true, message: 'Logged out successfully' });
    logger.info('User logged out');
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

export { router as authRoutes }; 
