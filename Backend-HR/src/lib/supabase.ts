import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

// Supabase configuration - Use the correct environment variables
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('🔴 CRITICAL: Missing Supabase environment variables!');
  console.error('Required: NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY');
  console.error('Please create Backend-HR/.env with these variables');
}

export const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co', 
  supabaseServiceKey || 'placeholder-key', 
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

// Test connection function
export async function testConnection(): Promise<boolean> {
  try {
    console.log('🔄 Testing Supabase connection...');
    console.log('📍 URL:', supabaseUrl ? '✅ Set' : '❌ Missing');
    console.log('🔑 Service Key:', supabaseServiceKey ? '✅ Set' : '❌ Missing');
    
    // Fix the query syntax - use proper count syntax
    const { count, error } = await supabase
      .from('organizations')
      .select('*', { count: 'exact', head: true });
    
    if (error) {
      console.error('🔴 Supabase connection test failed:', error.message);
      return false;
    }
    
    console.log('✅ Supabase connection successful');
    console.log(`📊 Found ${count || 0} organizations`);
    return true;
  } catch (error) {
    console.error('🔴 Supabase connection failed:', error);
    return false;
  }
}

// Database types for TypeScript
export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string;
          name: string;
          industry: string;
          created_at: string;
          updated_at: string;
          description?: string;
        };
        Insert: {
          id?: string;
          name: string;
          industry: string;
          created_at?: string;
          updated_at?: string;
          description?: string;
        };
        Update: {
          id?: string;
          name?: string;
          industry?: string;
          created_at?: string;
          updated_at?: string;
          description?: string;
        };
      };
      profiles: {
        Row: {
          id: string;
          email: string;
          full_name?: string;
          organization_id?: string;
          role: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id: string;
          email: string;
          full_name?: string;
          organization_id?: string;
          role?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          email?: string;
          full_name?: string;
          organization_id?: string;
          role?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      agents: {
        Row: {
          id: string;
          name: string;
          description?: string;
          organization_id: string;
          provider: string;
          framework?: string;
          model: string;
          status: 'active' | 'inactive' | 'error';
          agent_type: 'custom' | 'nocode';
          endpoint?: string;
          no_code_platform?: string;
          api_key_hash?: string;
          created_at: string;
          updated_at: string;
          last_sync?: string;
        };
        Insert: {
          id?: string;
          name: string;
          description?: string;
          organization_id: string;
          provider: string;
          framework?: string;
          model: string;
          status?: 'active' | 'inactive' | 'error';
          agent_type: 'custom' | 'nocode';
          endpoint?: string;
          no_code_platform?: string;
          api_key_hash?: string;
          created_at?: string;
          updated_at?: string;
          last_sync?: string;
        };
        Update: {
          id?: string;
          name?: string;
          description?: string;
          organization_id?: string;
          provider?: string;
          framework?: string;
          model?: string;
          status?: 'active' | 'inactive' | 'error';
          agent_type?: 'custom' | 'nocode';
          endpoint?: string;
          no_code_platform?: string;
          api_key_hash?: string;
          created_at?: string;
          updated_at?: string;
          last_sync?: string;
        };
      };
      agent_metrics: {
        Row: {
          id: string;
          agent_id: string;
          total_tokens: number;
          input_tokens: number;
          output_tokens: number;
          total_cost: number;
          total_requests: number;
          average_latency: number;
          success_rate: number;
          timestamp: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          agent_id: string;
          total_tokens?: number;
          input_tokens?: number;
          output_tokens?: number;
          total_cost?: number;
          total_requests?: number;
          average_latency?: number;
          success_rate?: number;
          timestamp?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          agent_id?: string;
          total_tokens?: number;
          input_tokens?: number;
          output_tokens?: number;
          total_cost?: number;
          total_requests?: number;
          average_latency?: number;
          success_rate?: number;
          timestamp?: string;
          created_at?: string;
        };
      };
      agent_health: {
        Row: {
          id: string;
          agent_id: string;
          status: 'healthy' | 'warning' | 'critical';
          uptime: number;
          last_ping: string;
          response_time: number;
          error_rate: number;
          cpu_usage?: number;
          memory_usage?: number;
          created_at: string;
        };
        Insert: {
          id?: string;
          agent_id: string;
          status: 'healthy' | 'warning' | 'critical';
          uptime?: number;
          last_ping?: string;
          response_time?: number;
          error_rate?: number;
          cpu_usage?: number;
          memory_usage?: number;
          created_at?: string;
        };
        Update: {
          id?: string;
          agent_id?: string;
          status?: 'healthy' | 'warning' | 'critical';
          uptime?: number;
          last_ping?: string;
          response_time?: number;
          error_rate?: number;
          cpu_usage?: number;
          memory_usage?: number;
          created_at?: string;
        };
      };
      agent_errors: {
        Row: {
          id: string;
          agent_id: string;
          error_type: string;
          error_message: string;
          stack_trace?: string;
          context?: any;
          severity: 'low' | 'medium' | 'high' | 'critical';
          resolved: boolean;
          created_at: string;
        };
        Insert: {
          id?: string;
          agent_id: string;
          error_type: string;
          error_message: string;
          stack_trace?: string;
          context?: any;
          severity?: 'low' | 'medium' | 'high' | 'critical';
          resolved?: boolean;
          created_at?: string;
        };
        Update: {
          id?: string;
          agent_id?: string;
          error_type?: string;
          error_message?: string;
          stack_trace?: string;
          context?: any;
          severity?: 'low' | 'medium' | 'high' | 'critical';
          resolved?: boolean;
          created_at?: string;
        };
      };
      agent_security_events: {
        Row: {
          id: string;
          agent_id: string;
          event_type: string;
          severity: 'low' | 'medium' | 'high' | 'critical';
          description: string;
          source_ip?: string;
          user_agent?: string;
          metadata?: any;
          created_at: string;
        };
        Insert: {
          id?: string;
          agent_id: string;
          event_type: string;
          severity?: 'low' | 'medium' | 'high' | 'critical';
          description: string;
          source_ip?: string;
          user_agent?: string;
          metadata?: any;
          created_at?: string;
        };
        Update: {
          id?: string;
          agent_id?: string;
          event_type?: string;
          severity?: 'low' | 'medium' | 'high' | 'critical';
          description?: string;
          source_ip?: string;
          user_agent?: string;
          metadata?: any;
          created_at?: string;
        };
      };
      agent_compliance_logs: {
        Row: {
          id: string;
          agent_id: string;
          compliance_type: string;
          status: 'compliant' | 'non_compliant' | 'warning';
          details: string;
          metadata?: any;
          created_at: string;
        };
        Insert: {
          id?: string;
          agent_id: string;
          compliance_type: string;
          status: 'compliant' | 'non_compliant' | 'warning';
          details: string;
          metadata?: any;
          created_at?: string;
        };
        Update: {
          id?: string;
          agent_id?: string;
          compliance_type?: string;
          status?: 'compliant' | 'non_compliant' | 'warning';
          details?: string;
          metadata?: any;
          created_at?: string;
        };
      };
    };
  };
} 