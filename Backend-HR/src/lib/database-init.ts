import { testConnection } from './supabase';
import { logger } from '../utils/logger';

export async function initializeDatabase() {
  try {
    logger.info('🚀 Initializing database...');
    
    // Test connection with timeout
    const connectionPromise = testConnection();
    const timeoutPromise = new Promise<boolean>((_, reject) => 
      setTimeout(() => reject(new Error('Connection timeout')), 10000)
    );
    
    const connectionSuccessful = await Promise.race([connectionPromise, timeoutPromise]);
    
    if (!connectionSuccessful) {
      logger.warn('⚠️  Database connection failed, using empty mode');
      logger.info('📊 Backend will serve empty data until database is connected');
      return false;
    }

    logger.info('✅ Database connection successful');
    logger.info('📊 Database is ready (no default data created)');
    logger.info('🎉 Database initialization complete - showing empty state');
    return true;
  } catch (error: any) {
    logger.error('❌ Database initialization failed:', error.message);
    logger.warn('⚠️  Falling back to empty mode - all APIs will return empty data');
    return false;
  }
} 