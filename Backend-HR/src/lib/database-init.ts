import { supabase } from './supabase'
import { logger } from '../utils/logger'

export async function initializeDatabase() {
  try {
    logger.info('🚀 Initializing database...')

    // Test if we can connect to Supabase
    const { data: connectionTest, error: connectionError } = await supabase
      .from('agents')
      .select('count', { count: 'exact', head: true })

    if (connectionError) {
      logger.warn('⚠️  Database connection failed, using empty mode:', connectionError.message)
      return false
    }

    logger.info('✅ Database connection successful')
    logger.info('📊 Database is ready (no default data created)')
    logger.info('🎉 Database initialization complete - showing empty state')
    return true

  } catch (error) {
    logger.error('Database initialization failed:', error)
    return false
  }
} 