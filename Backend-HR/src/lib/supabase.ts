import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

// Supabase configuration
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-service-key';

if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.warn('⚠️  Supabase environment variables not set. Using mock values for development.');
}

export const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

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