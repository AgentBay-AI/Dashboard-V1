# Multi-stage build for production optimization
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Create a non-root user
RUN addgroup -g 1001 -S nodeuser && \
    adduser -S nodeuser -u 1001

# Set working directory
WORKDIR /app

# Copy built application and dependencies
COPY --from=builder --chown=nodeuser:nodeuser /app/dist ./dist
COPY --from=builder --chown=nodeuser:nodeuser /app/node_modules ./node_modules
COPY --from=builder --chown=nodeuser:nodeuser /app/package.json ./

# Create logs directory
RUN mkdir -p logs && chown nodeuser:nodeuser logs

# Switch to non-root user
USER nodeuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the application
CMD ["node", "dist/index.js"] 