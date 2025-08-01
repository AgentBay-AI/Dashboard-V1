import { Request, Response, NextFunction } from 'express';
import { trace, context, propagation, SpanKind } from '@opentelemetry/api';
import { logger } from '../utils/logger';

// Extend Request interface to include trace information
export interface TracedRequest extends Request {
  traceId?: string;
  spanId?: string;
  traceContext?: any;
}

/**
 * OTEL Trace Context Middleware
 * Extracts trace context from headers and propagates it through the request
 */
export const traceContextMiddleware = (req: TracedRequest, res: Response, next: NextFunction) => {
  try {
    // Extract trace context from incoming headers
    const activeContext = propagation.extract(context.active(), req.headers);
    
    // Get current span if available
    const span = trace.getActiveSpan();
    
    if (span) {
      const spanContext = span.spanContext();
      req.traceId = spanContext.traceId;
      req.spanId = spanContext.spanId;
      req.traceContext = {
        traceId: spanContext.traceId,
        spanId: spanContext.spanId,
        traceFlags: spanContext.traceFlags
      };
    }

    // Set trace headers in response for downstream services
    if (req.traceId) {
      res.setHeader('x-trace-id', req.traceId);
    }

    // Continue with the extracted context
    context.with(activeContext, () => {
      next();
    });
  } catch (error) {
    logger.warn('Failed to extract trace context:', error);
    next();
  }
};

/**
 * Create a traced span for specific operations
 */
export const createSpan = (name: string, req: TracedRequest, operation: () => Promise<any>) => {
  const tracer = trace.getTracer('hr-agent-backend');
  
  return tracer.startActiveSpan(name, {
    kind: SpanKind.SERVER,
    attributes: {
      'http.method': req.method,
      'http.url': req.url,
      'http.route': req.route?.path || req.path,
      'user.client_id': (req as any).clientId || 'unknown',
      'trace.source': 'backend'
    }
  }, async (span) => {
    try {
      const result = await operation();
      span.setStatus({ code: 1 }); // SUCCESS
      return result;
    } catch (error: any) {
      span.setStatus({ 
        code: 2, // ERROR
        message: error.message 
      });
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  });
};

/**
 * Add trace context to any object (for database storage)
 */
export const addTraceContext = (data: any, req: TracedRequest): any => {
  if (req.traceId) {
    return {
      ...data,
      trace_id: req.traceId,
      span_id: req.spanId,
      trace_context: req.traceContext
    };
  }
  return data;
}; 