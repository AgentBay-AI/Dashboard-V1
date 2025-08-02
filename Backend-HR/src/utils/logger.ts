import winston from 'winston';

interface CustomLogger extends winston.Logger {
    requestContext: (req: any) => {
        ip: string | undefined;
        method: string | undefined;
        url: string | undefined;
        userAgent: string | undefined;
        clientId: string | undefined;
        traceId: string | undefined;
    };
}

const logger = winston.createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
        })
    ]
}) as CustomLogger;

// Add request context if available
logger.requestContext = (req: any) => ({
    ip: req?.ip,
    method: req?.method,
    url: req?.originalUrl,
    userAgent: req?.headers?.['user-agent'],
    clientId: req?.clientId,
    traceId: req?.traceId
});

export { logger }; 