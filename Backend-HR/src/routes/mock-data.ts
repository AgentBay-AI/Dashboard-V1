import { Router, Request, Response, NextFunction } from 'express';

const router = Router();

// Mock agents data
const mockAgents = [
  {
    id: '8f9bee53-e8bb-44a3-b30a-fedb09dc86d6',
    name: 'Customer Support Bot',
    description: 'Handles customer inquiries and support tickets',
    organization_id: 'default',
    provider: 'openai',
    framework: 'langchain',
    model: 'gpt-4',
    status: 'active',
    agent_type: 'custom',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_sync: new Date().toISOString(),
    metrics: {
      performance: 95,
      cost: 587,
      requests: 12450,
      latency: 250,
      uptime: 99.8,
      health_status: 'healthy'
    }
  },
  {
    id: 'content-gen-123',
    name: 'Content Generator',
    description: 'Generates marketing content and blog posts',
    organization_id: 'default',
    provider: 'anthropic',
    framework: 'custom',
    model: 'claude-3-opus',
    status: 'active',
    agent_type: 'custom',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_sync: new Date().toISOString(),
    metrics: {
      performance: 88,
      cost: 400,
      requests: 5230,
      latency: 180,
      uptime: 97.2,
      health_status: 'healthy'
    }
  }
];

// Mock metrics storage
let mockMetrics: any[] = [];
let mockHealthData: any[] = [];
let mockErrors: any[] = [];

// GET /api/mock/agents - Return mock agents
router.get('/agents', (req: Request, res: Response): void => {
  res.json({
    agents: mockAgents,
    total: mockAgents.length,
    timestamp: new Date().toISOString()
  });
});

// GET /api/mock/agents/:id/metrics - Return mock metrics for specific agent
router.get('/agents/:id/metrics', (req: Request, res: Response): void => {
  const { id } = req.params;
  const { timeframe = '24h' } = req.query;

  // Generate some mock metrics data
  const mockMetricsData = Array.from({ length: 10 }, (_, i) => ({
    id: `metric-${i}`,
    total_tokens: Math.floor(Math.random() * 1000) + 100,
    input_tokens: Math.floor(Math.random() * 500) + 50,
    output_tokens: Math.floor(Math.random() * 500) + 50,
    total_cost: Math.random() * 0.01,
    total_requests: Math.floor(Math.random() * 100) + 10,
    average_latency: Math.random() * 500 + 100,
    success_rate: Math.random() * 20 + 80,
    timestamp: new Date(Date.now() - i * 3600000).toISOString(),
    created_at: new Date(Date.now() - i * 3600000).toISOString()
  }));

  const mockHealthDataArray = Array.from({ length: 5 }, (_, i) => ({
    id: `health-${i}`,
    status: ['healthy', 'warning', 'critical'][Math.floor(Math.random() * 3)],
    uptime: Math.random() * 100,
    response_time: Math.random() * 300 + 100,
    error_rate: Math.random() * 10,
    cpu_usage: Math.random() * 100,
    memory_usage: Math.random() * 100,
    created_at: new Date(Date.now() - i * 3600000).toISOString()
  }));

  const mockErrorsData = Array.from({ length: 3 }, (_, i) => ({
    id: `error-${i}`,
    error_type: ['APIError', 'NetworkError', 'ValidationError'][i % 3],
    error_message: 'Sample error message',
    severity: ['low', 'medium', 'high'][i % 3],
    created_at: new Date(Date.now() - i * 3600000).toISOString()
  }));

  res.json({
    agent_id: id,
    timeframe,
    metrics: mockMetricsData,
    health: mockHealthDataArray,
    errors: mockErrorsData,
    summary: {
      total_requests: mockMetricsData.reduce((sum, m) => sum + m.total_requests, 0),
      total_cost: mockMetricsData.reduce((sum, m) => sum + m.total_cost, 0),
      average_latency: mockMetricsData.reduce((sum, m) => sum + m.average_latency, 0) / mockMetricsData.length,
      error_count: mockErrorsData.length,
      uptime_average: mockHealthDataArray.reduce((sum, h) => sum + h.uptime, 0) / mockHealthDataArray.length
    },
    timestamp: new Date().toISOString()
  });
});

// POST /api/mock/log - Store mock data (just log it)
router.post('/log', (req: Request, res: Response, next: NextFunction): void => {
  try {
    const { type, data } = req.body;

    console.log(`📊 Mock ${type} logged:`, data);

    // Store in mock arrays
    switch (type) {
      case 'metrics':
        mockMetrics.push({ ...data, id: Date.now().toString(), created_at: new Date().toISOString() });
        break;
      case 'error':
        mockErrors.push({ ...data, id: Date.now().toString(), created_at: new Date().toISOString() });
        break;
      case 'security':
      case 'compliance':
        console.log(`🔒 ${type} event:`, data);
        break;
    }

    res.status(201).json({
      success: true,
      message: `${type} logged successfully (mock)`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error as any);
  }
});

// POST /api/mock/health - Store mock health data
router.post('/health', (req: Request, res: Response, next: NextFunction): void => {
  try {
    console.log('💚 Mock health logged:', req.body);

    mockHealthData.push({ 
      ...req.body, 
      id: Date.now().toString(), 
      created_at: new Date().toISOString() 
    });

    res.status(201).json({
      success: true,
      message: 'Health status logged successfully (mock)',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error as any);
  }
});

// GET /api/mock/stats - Get mock stats
router.get('/stats', (req: Request, res: Response): void => {
  res.json({
    metrics_count: mockMetrics.length,
    health_records: mockHealthData.length,
    errors_count: mockErrors.length,
    last_activity: mockMetrics.length > 0 ? mockMetrics[mockMetrics.length - 1].created_at : null
  });
});

export { router as mockDataRoutes }; 
