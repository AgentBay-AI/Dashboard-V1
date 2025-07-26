import { supabase, testConnection } from './supabase'
import { logger } from '../utils/logger'

export async function initializeDatabase() {
  try {
    logger.info('🚀 Initializing database...')

    // Test connection using dedicated function
    const connectionSuccessful = await testConnection()
    
    if (!connectionSuccessful) {
      logger.warn('⚠️  Database connection failed, using empty mode')
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