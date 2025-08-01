import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { NodeSDK } from '@opentelemetry/sdk-node';

// Initialize OpenTelemetry with basic configuration
const sdk = new NodeSDK({
  instrumentations: [getNodeAutoInstrumentations({
    // Disable instrumentations that might cause issues
    '@opentelemetry/instrumentation-fs': {
      enabled: false,
    },
  })],
});

// Start the SDK
try {
  sdk.start();
  console.log('OpenTelemetry started successfully');
} catch (error) {
  console.warn('Failed to start OpenTelemetry:', error);
}

export default sdk; 