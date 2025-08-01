import { testConnection, supabase } from './supabase';
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

    // Check if tables exist - don't auto-create them
    await checkTablesExist();

    logger.info('✅ Database connection successful');
    logger.info('📊 Database is ready with AI Agent tracking tables');
    logger.info('🎉 Database initialization complete - showing empty state');
    return true;
  } catch (error: any) {
    logger.error('❌ Database initialization failed:', error.message);
    logger.warn('⚠️  Falling back to empty mode - all APIs will return empty data');
    return false;
  }
}

async function checkTablesExist() {
  try {
    logger.info('📦 Checking AI Agent tracking tables...');

    // List of required tables
    const requiredTables = [
      'sdk_agents',
      'conversations', 
      'llm_usage',
      'security_events',
      'compliance_audit',
      'failed_sessions',
      'api_keys'
    ];

    const missingTables = [];

    // Check if each table exists by trying a simple query
    for (const tableName of requiredTables) {
      try {
        const { error } = await supabase
          .from(tableName)
          .select('count', { count: 'exact', head: true })
          .limit(0);
        
        if (error) {
          missingTables.push(tableName);
        }
      } catch (error) {
        missingTables.push(tableName);
      }
    }

    if (missingTables.length > 0) {
      logger.warn(`⚠️  Missing tables: ${missingTables.join(', ')}`);
      logger.info('📋 Please run the SQL script from database-setup.sql in your Supabase SQL Editor');
      logger.info('🔗 Supabase Dashboard: https://supabase.com/dashboard/project/[your-project]/sql');
    } else {
      logger.info('✅ All required tables exist');
    }

    logger.info('✅ Database check complete');
  } catch (error: any) {
    logger.warn('⚠️  Could not verify table existence:', error.message);
    logger.info('📋 Please ensure tables are created using database-setup.sql');
  }
} 