import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';

// Middleware to validate request payload schemas
export function validateSchema(schema: ZodSchema) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (result.success) {
      // Use validated/coerced data
      req.body = result.data;
      return next();
    }

    // Forward a standardized validation error to the central error handler
    const err: any = new Error('Validation Error');
    err.name = 'ValidationError';
    err.statusCode = 400;
    err.code = 'ZOD_VALIDATION';
    // Attach structured issues for debugging (consumed by error handler in non-prod)
    err.details = result.error.issues;
    return next(err);
  };
}
