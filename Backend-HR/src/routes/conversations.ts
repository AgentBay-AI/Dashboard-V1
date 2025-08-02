import express from 'express';
import { supabase } from '../lib/supabase';
import { 
  conversationStartSchema, 
  conversationEndSchema, 
  conversationMessageSchema, 
  conversationResumeSchema, 
  failedSessionSchema, 
  sessionUpdateSchema 
} from '../lib/schemas';
import { requirePermission, AuthenticatedRequest, authenticateApiKey } from '../middleware/auth';
import { addTraceContext } from '../middleware/tracing';
import { logger } from '../utils/logger';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticateApiKey);

// POST /conversations/start
router.post('/start', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = conversationStartSchema.parse(req.body);
    
    const conversationData = addTraceContext({
      ...validatedData,
      start_time: new Date().toISOString(),
      status: 'active'
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .insert(conversationData)
      .select();

    if (error) {
      logger.error('Failed to start conversation', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Conversation started', { session_id: validatedData.session_id });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to start conversation', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/end
router.post('/end', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = conversationEndSchema.parse(req.body);
    
    const updateData = addTraceContext({
      status: 'completed',
      end_time: validatedData.end_time || new Date().toISOString(),
      quality_score: validatedData.quality_score,
      metadata: validatedData.metadata,
      updated_at: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .update(updateData)
      .eq('session_id', validatedData.session_id)
      .select();

    if (error) {
      logger.error('Failed to end conversation', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Conversation ended', { session_id: validatedData.session_id });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to end conversation', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/message
router.post('/message', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = conversationMessageSchema.parse(req.body);
    
    const messageData = addTraceContext({
      ...validatedData,
      timestamp: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('messages')
      .insert(messageData)
      .select();

    if (error) {
      logger.error('Failed to add message', { error, session_id: validatedData.session_id });
      throw error;
    }

    // Update total_messages count in conversations
    const { error: updateError } = await supabase
      .from('conversations')
      .update({ 
        total_messages: supabase.rpc('increment_messages', { session_id: validatedData.session_id }),
        updated_at: new Date().toISOString()
      })
      .eq('session_id', validatedData.session_id);

    if (updateError) {
      logger.warn('Failed to update message count', { error: updateError, session_id: validatedData.session_id });
    }

    logger.info('Message added', { session_id: validatedData.session_id, message_type: validatedData.message_type });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to add message', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/resume
router.post('/resume', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = conversationResumeSchema.parse(req.body);
    
    const updateData = addTraceContext({
      status: 'resumed',
      metadata: validatedData.metadata,
      updated_at: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .update(updateData)
      .eq('session_id', validatedData.session_id)
      .select();

    if (error) {
      logger.error('Failed to resume conversation', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Conversation resumed', { session_id: validatedData.session_id });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to resume conversation', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/failed-session
router.post('/failed-session', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = failedSessionSchema.parse(req.body);
    
    const updateData = addTraceContext({
      status: 'failed',
      end_time: new Date().toISOString(),
      metadata: {
        failure_reason: validatedData.failure_reason,
        error_details: validatedData.error_details
      },
      updated_at: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .update(updateData)
      .eq('session_id', validatedData.session_id)
      .select();

    if (error) {
      logger.error('Failed to mark session as failed', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Session marked as failed', { session_id: validatedData.session_id, reason: validatedData.failure_reason });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to mark session as failed', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/local-expired
router.post('/local-expired', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = sessionUpdateSchema.parse({ ...req.body, status: 'expired' });
    
    const updateData = addTraceContext({
      status: 'expired',
      end_time: new Date().toISOString(),
      metadata: validatedData.metadata,
      updated_at: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .update(updateData)
      .eq('session_id', validatedData.session_id)
      .select();

    if (error) {
      logger.error('Failed to mark session as expired', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Session marked as expired', { session_id: validatedData.session_id });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to mark session as expired', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/evicted
router.post('/evicted', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const validatedData = sessionUpdateSchema.parse({ ...req.body, status: 'evicted' });
    
    const updateData = addTraceContext({
      status: 'evicted',
      end_time: new Date().toISOString(),
      metadata: validatedData.metadata,
      updated_at: new Date().toISOString()
    }, req);

    const { data, error } = await supabase
      .from('conversations')
      .update(updateData)
      .eq('session_id', validatedData.session_id)
      .select();

    if (error) {
      logger.error('Failed to mark session as evicted', { error, session_id: validatedData.session_id });
      throw error;
    }

    logger.info('Session marked as evicted', { session_id: validatedData.session_id });
    res.json({ success: true, data: data?.[0] });
  } catch (error: any) {
    logger.error('Failed to mark session as evicted', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /conversations/active
router.get('/active', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('view_active_conversations')
      .select('*')
      .order('start_time', { ascending: false });

    if (error) {
      logger.error('Failed to get active conversations', { error });
      throw error;
    }

    res.json({ success: true, data: data || [] });
  } catch (error: any) {
    logger.error('Failed to get active conversations', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /conversations/{session_id}/history
router.get('/:session_id/history', requirePermission('read'), async (req: AuthenticatedRequest, res) => {
  try {
    const { session_id } = req.params;
    
    const { data, error } = await supabase
      .from('messages')
      .select('*')
      .eq('session_id', session_id)
      .order('timestamp', { ascending: true });

    if (error) {
      logger.error('Failed to get conversation history', { error, session_id });
      throw error;
    }

    res.json({ success: true, data: data || [] });
  } catch (error: any) {
    logger.error('Failed to get conversation history', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /conversations/history (for bulk history logging)
router.post('/history', requirePermission('write'), async (req: AuthenticatedRequest, res) => {
  try {
    const { session_id, messages } = req.body;
    
    if (!session_id || !Array.isArray(messages)) {
      return res.status(400).json({ 
        success: false, 
        error: 'session_id and messages array are required' 
      });
    }

    const messagesWithTimestamp = messages.map(msg => 
      addTraceContext({
        ...msg,
        session_id,
        timestamp: msg.timestamp || new Date().toISOString()
      }, req)
    );

    const { data, error } = await supabase
      .from('messages')
      .insert(messagesWithTimestamp)
      .select();

    if (error) {
      logger.error('Failed to add conversation history', { error, session_id });
      throw error;
    }

    logger.info('Conversation history added', { session_id, message_count: messages.length });
    res.json({ success: true, data });
  } catch (error: any) {
    logger.error('Failed to add conversation history', { error });
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router; 