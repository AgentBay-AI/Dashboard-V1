import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const router = express.Router();

// JWT secret from environment
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

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
    const { data: existingUser } = await supabase
      .from('profiles')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (existingUser) {
      // Ensure client_id exists
      if (!existingUser.client_id) {
        const clientId = `client_${crypto.randomBytes(8).toString('hex')}`;
        await supabase.from('profiles').update({ client_id: clientId }).eq('id', existingUser.id);
        return { ...existingUser, client_id: clientId };
      }
      return existingUser;
    }

    // Create new user with a fresh client_id
    const clientId = `client_${crypto.randomBytes(8).toString('hex')}`;
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
      throw createError;
    }

    return newUser;
  } catch (error) {
    logger.error('Error finding/creating user:', error);
    throw error;
  }
}

// POST /api/auth/clerk/sync - called from frontend after Clerk sign-in
router.post('/clerk/sync', async (req, res) => {
  try {
    const { clerk_user_id, email, full_name } = clerkSyncSchema.parse(req.body);

    // Try existing by clerk_user_id first
    let { data: user } = await supabase
      .from('profiles')
      .select('*')
      .eq('clerk_user_id', clerk_user_id)
      .maybeSingle();

    if (!user) {
      // Fallback by email
      const { data: byEmail } = await supabase
        .from('profiles')
        .select('*')
        .eq('email', email)
        .maybeSingle();

      if (byEmail) {
        // Attach clerk id and ensure client_id exists
        const clientId = byEmail.client_id || `client_${crypto.randomBytes(8).toString('hex')}`;
        const { data: updated } = await supabase
          .from('profiles')
          .update({ clerk_user_id, client_id: clientId, full_name: full_name || byEmail.full_name })
          .eq('id', byEmail.id)
          .select('*')
          .single();
        user = updated!;
      } else {
        // Create new profile with fresh client_id
        const clientId = `client_${crypto.randomBytes(8).toString('hex')}`;
        const { data: created } = await supabase
          .from('profiles')
          .insert({ email, full_name: full_name || email.split('@')[0], role: 'user', client_id: clientId, clerk_user_id })
          .select('*')
          .single();
        user = created!;
      }
    }

    // Optionally mint a dashboard API key on first sync if none exists for this client_id
    const { data: existingKey } = await supabase
      .from('api_keys')
      .select('id')
      .eq('client_id', user.client_id)
      .limit(1)
      .maybeSingle();

    let dashboardKey: string | undefined;
    if (!existingKey) {
      const rawKey = `sk-${crypto.randomBytes(32).toString('hex')}`;
      const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
      await supabase.from('api_keys').insert({
        key_hash: keyHash,
        client_id: user.client_id,
        client_name: `${user.full_name || 'User'} Dashboard`,
        permissions: JSON.stringify(["read","write","sdk"]),
        rate_limit_per_minute: 3000,
        is_active: true
      });
      dashboardKey = rawKey; // Only returned once
    }

    res.json({ success: true, data: { client_id: user.client_id, user_id: user.id, email: user.email, dashboard_key: dashboardKey } });
  } catch (error: any) {
    logger.error('Clerk sync failed:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /api/auth/login - Email/password login
router.post('/login', async (req, res) => {
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
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// POST /api/auth/google - Google OAuth login
router.post('/google', async (req, res) => {
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
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

// POST /api/auth/logout - Logout
router.post('/logout', async (req, res) => {
  try {
    res.json({ success: true, message: 'Logged out successfully' });
    logger.info('User logged out');
  } catch (error) {
    logger.error('Logout failed:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// GET /api/auth/me - Get current user info
router.get('/me', async (req, res) => {
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
      return res.status(401).json({ error: 'Invalid token' });
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
    res.status(401).json({ error: 'Invalid token' });
  }
});

export { router as authRoutes }; 