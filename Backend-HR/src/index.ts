import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { agentRoutes } from './routes/agents';
import { mockDataRoutes } from './routes/mock-data';
import { frontendApiRoutes } from './routes/frontend-api';
import { analyticsApiRoutes } from './routes/analytics-api';
import { authRoutes } from './routes/auth';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import { initializeDatabase } from './lib/database-init';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://hr-agent-frontend-1080649900100.me-central1.run.app',
    process.env.FRONTEND_URL || 'http://localhost:3000'
  ],
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000, // limit each IP to 100 requests per windowMs in production
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'AI Agent Operations Platform API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/health',
      agents: '/api/agents',
      metrics: '/api/agents/log',
      health_log: '/api/agents/health'
    },
    docs: 'https://github.com/your-repo/ai-hr-agent'
  });
});

// API routes
app.use('/api/agents', agentRoutes);
app.use('/api/mock', mockDataRoutes);
app.use('/api/frontend', frontendApiRoutes);
app.use('/api/analytics', analyticsApiRoutes);
app.use('/api/auth', authRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The endpoint ${req.method} ${req.originalUrl} does not exist`,
    availableEndpoints: ['/health', '/api/agents', '/api/agents/log', '/api/agents/health']
  });
});

// Global error handler
app.use(errorHandler);

// Start server
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    port: PORT,
    timestamp: new Date().toISOString()
  });
  
  // Initialize database (non-blocking)
  try {
    await initializeDatabase();
  } catch (error) {
    logger.warn('Database initialization failed, continuing with mock mode:', error);
  }
});

export default app; 