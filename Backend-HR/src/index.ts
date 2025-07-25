import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import agentRoutes from './routes/agents';

// Load environment variables
dotenv.config();

// Set default values for required environment variables
process.env.NODE_ENV = process.env.NODE_ENV || 'production';
process.env.FRONTEND_URL = process.env.FRONTEND_URL || 'https://hr-agent-frontend-1080649900100.me-central1.run.app';

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://hr-agent-frontend-1080649900100.me-central1.run.app',
    process.env.FRONTEND_URL || ''
  ].filter(Boolean),
  credentials: true
}));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Basic route
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'AI Agent Operations Platform API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      agents: '/api/agents',
      log_metrics: '/api/agents/log',
      log_health: '/api/agents/health'
    }
  });
});

// API Routes
app.use('/api/agents', agentRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    message: `The endpoint ${req.method} ${req.originalUrl} does not exist`
  });
});

// Global error handler
app.use((err: any, req: any, res: any, next: any) => {
  console.error('Global error handler:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

app.listen(port, () => {
  console.log(`🚀 AI Agent Operations Platform API is running on port ${port}`);
  console.log(`📊 Dashboard: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log(`🔗 Environment: ${process.env.NODE_ENV || 'development'}`);
}); 