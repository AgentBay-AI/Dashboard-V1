import { createClient } from '@supabase/supabase-js'
import dotenv from 'dotenv'

dotenv.config()

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://xedlnzqfwdgkummqeauv.supabase.co'
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'mock-key-for-development'

// Create Supabase client with service role key for backend operations
export const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
})

// Database types for type safety
export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string
          name: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          created_at?: string
          updated_at?: string
        }
      }
      profiles: {
        Row: {
          id: string
          organization_id: string | null
          email: string
          full_name: string | null
          avatar_url: string | null
          role: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          organization_id?: string | null
          email: string
          full_name?: string | null
          avatar_url?: string | null
          role?: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string | null
          email?: string
          full_name?: string | null
          avatar_url?: string | null
          role?: string
          created_at?: string
          updated_at?: string
        }
      }
      agents: {
        Row: {
          id: string
          organization_id: string
          name: string
          description: string | null
          agent_type: string
          provider: string | null
          model: string | null
          framework: string | null
          api_key_hash: string | null
          endpoint_url: string | null
          status: string
          created_by: string | null
          created_at: string
          updated_at: string
          last_activity: string | null
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          description?: string | null
          agent_type?: string
          provider?: string | null
          model?: string | null
          framework?: string | null
          api_key_hash?: string | null
          endpoint_url?: string | null
          status?: string
          created_by?: string | null
          created_at?: string
          updated_at?: string
          last_activity?: string | null
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          description?: string | null
          agent_type?: string
          provider?: string | null
          model?: string | null
          framework?: string | null
          api_key_hash?: string | null
          endpoint_url?: string | null
          status?: string
          created_by?: string | null
          created_at?: string
          updated_at?: string
          last_activity?: string | null
        }
      }
      agent_metrics: {
        Row: {
          id: string
          agent_id: string
          timestamp: string
          prompt_tokens: number
          completion_tokens: number
          total_tokens: number
          cost: number
          latency_ms: number | null
          success: boolean
          model: string | null
          provider: string | null
          operation: string | null
          metadata: any | null
        }
        Insert: {
          id?: string
          agent_id: string
          timestamp?: string
          prompt_tokens?: number
          completion_tokens?: number
          cost?: number
          latency_ms?: number | null
          success?: boolean
          model?: string | null
          provider?: string | null
          operation?: string | null
          metadata?: any | null
        }
        Update: {
          id?: string
          agent_id?: string
          timestamp?: string
          prompt_tokens?: number
          completion_tokens?: number
          cost?: number
          latency_ms?: number | null
          success?: boolean
          model?: string | null
          provider?: string | null
          operation?: string | null
          metadata?: any | null
        }
      }
      agent_health: {
        Row: {
          id: string
          agent_id: string
          timestamp: string
          status: string
          memory_usage_mb: number | null
          cpu_usage_percent: number | null
          response_time_ms: number | null
          uptime_seconds: number | null
          error_count: number
          last_error: string | null
          metadata: any | null
        }
        Insert: {
          id?: string
          agent_id: string
          timestamp?: string
          status?: string
          memory_usage_mb?: number | null
          cpu_usage_percent?: number | null
          response_time_ms?: number | null
          uptime_seconds?: number | null
          error_count?: number
          last_error?: string | null
          metadata?: any | null
        }
        Update: {
          id?: string
          agent_id?: string
          timestamp?: string
          status?: string
          memory_usage_mb?: number | null
          cpu_usage_percent?: number | null
          response_time_ms?: number | null
          uptime_seconds?: number | null
          error_count?: number
          last_error?: string | null
          metadata?: any | null
        }
      }
    }
  }
} 