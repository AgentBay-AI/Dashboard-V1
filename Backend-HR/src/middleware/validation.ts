import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { ZodSchema } from 'zod';

// Middleware to validate request payload schemas
export function validateSchema(schema: ZodSchema) {
    return (req: Request, res: Response, next: NextFunction): void => {
        try {
            const result = schema.parse(req.body);
            req.body = result; // Use validated data
            next();
        } catch (error: any) {
            logger.warn('Validation failed:', {
                path: req.path,
                error: error.errors || error.message,
                body: req.body
            });
            
            res.status(400).json({
                error: 'Validation failed',
                message: 'Request body validation failed',
                details: error.errors || error.message
            });
        }
    };
} 