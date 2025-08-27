import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface CustomError extends Error {
  statusCode?: number;
  code?: string;
}

export interface ErrorResponse {
  error: string;
  status: number;
  timestamp: string;
  stack?: string;
  details?: CustomError;
}

export const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  const timestamp = new Date().toISOString();
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';

  // Log the error
  logger.error('Error occurred:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    timestamp
  });

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized';
  } else if (err.code === 'ECONNREFUSED') {
    statusCode = 503;
    message = 'Service Unavailable - Database connection failed';
  }

  // Don't send stack trace in production
  const response: ErrorResponse = {
    error: message,
    status: statusCode,
    timestamp
  };

  if (process.env.NODE_ENV !== 'production') {
    response.stack = err.stack;
    response.details = { name: err.name, message: err.message, code: err.code };
  }

  res.status(statusCode).json(response);
}; 
