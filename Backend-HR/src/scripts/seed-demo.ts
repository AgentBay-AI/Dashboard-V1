import 'dotenv/config';
import { supabase } from '../lib/supabase';
import nodeCrypto from 'node:crypto';

async function main() {
  const clientId = process.env.SEED_CLIENT_ID || 'current_frontend_client';

  console.log('Seeding demo data for client_id:', clientId);

  // 1) Ensure at least one organization
  const orgName = 'Demo Org';
  let orgId: string | null = null;
  {
    const { data: existingOrgs } = await supabase
      .from('organizations')
      .select('id, name, client_id')
      .eq('client_id', clientId)
      .limit(1);

    if (existingOrgs && existingOrgs.length > 0) {
      orgId = existingOrgs[0].id;
      console.log('Using existing organization:', orgId);
    } else {
      const { data: org, error } = await supabase
        .from('organizations')
        .insert({ name: orgName, plan: 'Professional', client_id: clientId, description: 'Demo organization for testing' })
        .select()
        .single();
      if (error) throw error;
      orgId = org.id;
      console.log('Created organization:', orgId);
    }
  }

  if (!orgId) throw new Error('Failed to get or create organization');

  // 2) Create agents if none
  const agentsToEnsure = [
    { name: 'Support Bot', description: 'Handles support tickets', agent_type: 'coded', platform: 'custom' },
    { name: 'Sales Assistant', description: 'Assists in sales', agent_type: 'coded', platform: 'custom' }
  ];

  const agentIds: string[] = [];
  {
    const { data: existingAgents } = await supabase
      .from('agents')
      .select('agent_id, name')
      .eq('client_id', clientId)
      .eq('organization_id', orgId)
      .limit(10);

    if (existingAgents && existingAgents.length >= 2) {
      existingAgents.slice(0, 2).forEach(a => agentIds.push(a.agent_id));
      console.log('Using existing agents:', agentIds);
    } else {
      for (const a of agentsToEnsure) {
        const { data: agent, error } = await supabase
          .from('agents')
          .insert({
            agent_id: nodeCrypto.randomUUID(),
            client_id: clientId,
            organization_id: orgId,
            name: a.name,
            description: a.description,
            agent_type: a.agent_type,
            platform: a.platform,
            status: 'active',
            sdk_version: '1.0.0',
            registration_time: new Date().toISOString(),
            metadata: { useCase: a.description, llmProviders: ['openai', 'anthropic'], createdViaSetup: true }
          })
          .select()
          .single();
        if (error) throw error;
        agentIds.push(agent.agent_id);
      }
      console.log('Created agents:', agentIds);
    }
  }

  // Helper to random int
  const randInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;

  // 3) Seed agent_activity (10 recent)
  for (const agentId of agentIds) {
    const activities = Array.from({ length: 5 }).map((_, i) => ({
      agent_id: agentId,
      client_id: clientId,
      activity_type: i % 2 === 0 ? 'session_completed' : 'session_failed',
      details: { note: 'demo activity' },
      timestamp: new Date(Date.now() - i * 3600_000).toISOString()
    }));
    const { error } = await supabase.from('agent_activity').insert(activities);
    if (error) console.warn('agent_activity insert warning:', error.message);
  }

  // 4) Seed agent_metrics (some recent rows)
  for (const agentId of agentIds) {
    const metrics = Array.from({ length: 5 }).map((_, i) => ({
      id: nodeCrypto.randomUUID(),
      agent_id: agentId,
      client_id: clientId,
      total_tokens: randInt(500, 5000),
      input_tokens: randInt(200, 3000),
      output_tokens: randInt(100, 2000),
      total_cost: Math.random() * 2,
      total_requests: randInt(5, 50),
      average_latency: randInt(100, 1200),
      success_rate: randInt(70, 99),
      created_at: new Date(Date.now() - i * 86400_000).toISOString()
    }));
    const { error } = await supabase.from('agent_metrics').insert(metrics);
    if (error) console.warn('agent_metrics insert warning:', error.message);
  }

  // 5) Seed agent_health
  for (const agentId of agentIds) {
    const health = Array.from({ length: 3 }).map((_, i) => ({
      id: nodeCrypto.randomUUID(),
      agent_id: agentId,
      client_id: clientId,
      status: 'healthy',
      uptime: randInt(90, 100),
      last_ping: new Date().toISOString(),
      response_time: randInt(100, 800),
      error_rate: randInt(0, 5),
      cpu_usage: randInt(30, 80),
      memory_usage: randInt(40, 85),
      created_at: new Date(Date.now() - i * 3600_000).toISOString()
    }));
    const { error } = await supabase.from('agent_health').insert(health);
    if (error) console.warn('agent_health insert warning:', error.message);
  }

  // 6) Seed agent_errors
  for (const agentId of agentIds) {
    const errors = Array.from({ length: 2 }).map(() => ({
      id: nodeCrypto.randomUUID(),
      agent_id: agentId,
      client_id: clientId,
      error_type: 'runtime_error',
      error_message: 'Demo error message',
      severity: 'low',
      resolved: Math.random() > 0.5,
      created_at: new Date().toISOString()
    }));
    const { error } = await supabase.from('agent_errors').insert(errors);
    if (error) console.warn('agent_errors insert warning:', error.message);
  }

  // 7) Seed conversations and messages
  const agentToSessions: Record<string, string[]> = {};
  for (const agentId of agentIds) {
    const sessions = Array.from({ length: 3 }).map((_, i) => ({
      session_id: nodeCrypto.randomUUID(),
      agent_id: agentId,
      client_id: clientId,
      start_time: new Date(Date.now() - (i + 1) * 7200_000).toISOString(),
      end_time: new Date(Date.now() - (i + 1) * 7100_000).toISOString(),
      status: i % 2 === 0 ? 'ended' : 'failed',
      metadata: { channel: 'web' }
    }));
    const { data: convs, error } = await supabase
      .from('conversations')
      .insert(sessions)
      .select();
    if (error) console.warn('conversations insert warning:', error.message);

    agentToSessions[agentId] = (convs || []).map(c => c.session_id);

    if (convs) {
      for (const c of convs) {
        const msgs = [
          { session_id: c.session_id, timestamp: new Date().toISOString(), content: 'Hello', role: 'user' },
          { session_id: c.session_id, timestamp: new Date().toISOString(), content: 'Hi, how can I help?', role: 'assistant', metadata: { quality_score: 4.8 } }
        ];
        const { error: merr } = await supabase.from('messages').insert(msgs);
        if (merr) console.warn('messages insert warning:', merr.message);
      }
    }
  }

  // 8) Seed llm_usage (spread over months for breakdown)
  const providers = [
    { provider: 'openai', model: 'gpt-4o' },
    { provider: 'anthropic', model: 'claude-3.5-sonnet' },
    { provider: 'google', model: 'gemini-1.5-pro' }
  ];

  for (const agentId of agentIds) {
    const sessions = agentToSessions[agentId] || [];
    const sessionIdForAgent = sessions[0] || nodeCrypto.randomUUID();
    for (let m = 0; m < 12; m++) {
      const date = new Date();
      date.setMonth(date.getMonth() - m);
      for (const p of providers) {
        const input = randInt(500, 5000);
        const output = randInt(300, 3000);
        const cost = (input * 0.0005 + output * 0.001).toFixed(6); // rough demo
        const { error } = await supabase.from('llm_usage').insert({
          session_id: sessionIdForAgent,
          agent_id: agentId,
          client_id: clientId,
          timestamp: date.toISOString(),
          provider: p.provider,
          model: p.model,
          tokens_input: input,
          tokens_output: output,
          cost
        });
        if (error) console.warn('llm_usage insert warning:', error.message);
      }
    }
  }

  console.log('Demo data seeding complete.');
}

main().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
}); 