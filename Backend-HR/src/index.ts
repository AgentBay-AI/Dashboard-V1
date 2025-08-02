// Initialize OTEL before other imports
import './telemetry';

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { logger } from './utils/logger';
import agentRoutes from './routes/agent-tracking';
import apiKeyRoutes from './routes/api-keys';
import conversationRoutes from './routes/conversations';
import metricsRoutes from './routes/metrics';
import { llmAnalyticsRoutes } from './routes/llm-analytics';
import { addTraceContext } from './middleware/tracing';

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(express.json());

// Add trace context to all requests
app.use((req, res, next) => {
    req.body = addTraceContext(req.body || {}, req);
    next();
});

// Routes
app.use('/api/agents', agentRoutes);
app.use('/api/keys', apiKeyRoutes);
app.use('/api/conversations', conversationRoutes);
app.use('/api/metrics', metricsRoutes);
app.use('/api/llm-usage', llmAnalyticsRoutes);

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred'
    });
});

app.listen(port, () => {
    logger.info(`Server running on port ${port}`);
}); 