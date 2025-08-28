
import { Request, Response, NextFunction } from 'express';
import { trace, context, propagation, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { randomBytes } from 'crypto';
import { logger } from '../utils/logger';

// Trace context for OpenTelemetry propagation
export interface TraceContext {
  traceId: string;
  spanId: string;
  traceFlags: number;
}

// Extend Request interface to include trace information
export interface TracedRequest extends Request {
  traceId?: string;
  spanId?: string;
  traceContext?: TraceContext;
}

/**
 * OTEL Trace Context Middleware
 * Extracts trace context from headers and propagates it through the request
 */
export const traceContextMiddleware = (req: TracedRequest, res: Response, next: NextFunction) => {
  try {
    const tracer = trace.getTracer('hr-agent-backend');

    // Extract W3C context and start a SERVER span as the canonical request span
    const extracted = propagation.extract(context.active(), req.headers);

    context.with(extracted, () => {
      tracer.startActiveSpan(
        `${req.method} ${req.path}`,
        {
          kind: SpanKind.SERVER,
          attributes: {
            'http.method': req.method,
            'http.url': req.url,
            'http.route': req.route?.path || req.path,
            'http.target': req.originalUrl || req.url,
            'net.peer.ip': req.ip,
            'trace.source': 'backend'
          }
        },
        (span) => {
          // Correlate response header and request fields with the actual span's trace id
          const sc = span.spanContext();
          req.traceId = sc.traceId;
          req.spanId = sc.spanId;
          req.traceContext = { traceId: sc.traceId, spanId: sc.spanId, traceFlags: sc.traceFlags };
          res.setHeader('x-trace-id', sc.traceId);

          // End span when response finishes, and set status based on HTTP code
          res.on('finish', () => {
            const status = res.statusCode;
            if (status >= 500) {
              span.setStatus({ code: SpanStatusCode.ERROR, message: `HTTP ${status}` });
            } else {
              span.setStatus({ code: SpanStatusCode.OK });
            }
            span.end();
          });

          next();
        }
      );
    });
  } catch (error) {
    logger.warn('Failed to start trace context:', error);
    next();
  }
};

/**
 * Create a traced span for specific operations
 */
export const createSpan = (name: string, req: TracedRequest, operation: () => Promise<any>) => {
  const tracer = trace.getTracer('hr-agent-backend');
  
  return tracer.startActiveSpan(name, {
    // Internal spans for app-level operations
    kind: SpanKind.INTERNAL,
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
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error: any) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: error?.message });
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
export const addTraceContext = <T>(
  data: T,
  req: TracedRequest
): T & { trace_id?: string; span_id?: string; trace_context?: TraceContext } => {
  if (!req.traceId) return data as any;

  const enriched: any = { ...data, trace_id: req.traceId };
  if (req.spanId) enriched.span_id = req.spanId;
  if (req.traceContext) enriched.trace_context = req.traceContext;
  return enriched;
};
