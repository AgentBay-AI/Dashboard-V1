// Initialize OTEL before other imports
import './telemetry';

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/errorHandler';
import agentRoutes from './routes/agent-tracking';
import apiKeyRoutes from './routes/api-keys';
import conversationRoutes from './routes/conversations';
import metricsRoutes from './routes/metrics';
import llmAnalyticsRoutes from './routes/llm-analytics';
import agentsRouter from './routes/agents';
import organizationsRouter from './routes/organizations';
import setupOrgsRouter from './routes/setup-organizations';
import { addTraceContext } from './middleware/tracing';
import { analyticsApiRoutes } from './routes/analytics-api';
import sdkRouter from './routes/sdk';
import { authRoutes } from './routes/auth';
import uptimeRouter from './routes/uptime';

const app = express();
const port = process.env.PORT || 8081;

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
app.use('/api/auth', authRoutes);
app.use('/api/agents', agentsRouter);
app.use('/api/agents', agentRoutes);
app.use('/api/keys', apiKeyRoutes);
app.use('/api/conversations', conversationRoutes);
app.use('/api/metrics', metricsRoutes);
app.use('/api/llm-usage', llmAnalyticsRoutes);
app.use('/api/organizations', organizationsRouter);
app.use('/api/setup', setupOrgsRouter); // Temporary setup endpoint
app.use('/api/dashboard', analyticsApiRoutes);
app.use('/api/sdk', sdkRouter);
// Dedicated uptime namespace
app.use('/api/uptime', uptimeRouter);

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(errorHandler);

app.listen(port, () => {
    logger.info(`Server running on port ${port}`);
}); 
