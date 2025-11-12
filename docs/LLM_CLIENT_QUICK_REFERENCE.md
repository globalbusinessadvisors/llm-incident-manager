# LLM Client Architecture - Quick Reference

**Version**: 1.0.0
**Date**: 2025-11-12

---

## Quick Links

- [Architecture Spec](./LLM_CLIENT_ARCHITECTURE.md) - Complete architecture documentation
- [Implementation Guide](./LLM_CLIENT_IMPLEMENTATION_GUIDE.md) - Step-by-step implementation
- [Type Definitions](./llm-client-types.ts) - TypeScript types reference

---

## Class Hierarchy

```
BaseLLMClient (Abstract)
├── SentinelLLMClient     - Anomaly detection
├── ShieldLLMClient       - Security analysis
├── EdgeAgentLLMClient    - Edge processing
└── GovernanceLLMClient   - Compliance checking

ILLMProvider (Interface)
├── OpenAIProvider        - OpenAI/Azure OpenAI
├── AnthropicProvider     - Claude models
├── AzureOpenAIProvider   - Azure-specific
└── VertexAIProvider      - Google Vertex AI
```

---

## Configuration Quick Start

### Minimal Configuration

```typescript
import { ConfigLoader } from './config/ConfigLoader';
import { SentinelLLMClient } from './clients/sentinel/SentinelLLMClient';

// Load environment-specific config
const config = ConfigLoader.load(process.env.NODE_ENV || 'development');

// Create client
const client = new SentinelLLMClient(config);

// Use client
const analysis = await client.analyzeAnomaly(event);
```

### Environment Variables

```bash
# Required
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional
export LLM_DEFAULT_MODEL="gpt-4"
export LLM_BASE_URL="https://api.openai.com/v1"
export LOG_LEVEL="info"
```

### Configuration File Structure

```json
{
  "clientId": "unique-client-id",
  "clientName": "Display Name",
  "version": "1.0.0",
  "provider": { /* Provider config */ },
  "resilience": { /* Retry, circuit breaker, rate limit */ },
  "observability": { /* Logging, metrics, tracing */ },
  "features": { /* Feature flags */ },
  "environment": "production|staging|development"
}
```

---

## Client Usage Patterns

### Sentinel - Anomaly Detection

```typescript
const sentinelClient = new SentinelLLMClient(config);

// Analyze anomaly
const analysis = await sentinelClient.analyzeAnomaly({
  eventId: 'evt-001',
  timestamp: new Date().toISOString(),
  source: 'monitoring-system',
  metrics: {
    cpu_usage: 95,
    memory_usage: 85,
  },
  context: {
    service: 'api-gateway',
  },
});

console.log('Is Anomaly:', analysis.isAnomaly);
console.log('Severity:', analysis.severity); // P0-P4
console.log('Confidence:', analysis.confidence); // 0-1
console.log('Recommendations:', analysis.recommendations);
```

### Shield - Security Analysis

```typescript
const shieldClient = new ShieldLLMClient(config);

// Analyze threat
const threatAnalysis = await shieldClient.analyzeThreat({
  eventId: 'sec-001',
  timestamp: new Date().toISOString(),
  eventType: 'suspicious_activity',
  payload: 'SELECT * FROM users WHERE id=1 OR 1=1--',
  context: {
    userId: 'user-123',
    ipAddress: '192.168.1.100',
  },
});

console.log('Is Threat:', threatAnalysis.isThreat);
console.log('Threat Level:', threatAnalysis.threatLevel);
console.log('Mitigation:', threatAnalysis.mitigationSteps);
```

### Edge-Agent - Distributed Processing

```typescript
const edgeClient = new EdgeAgentLLMClient(config);

// Process locally with fallback
const result = await edgeClient.processLocalInference({
  requestId: 'edge-req-001',
  model: 'gpt-3.5-turbo',
  input: 'Analyze this log entry',
  context: {
    nodeId: 'edge-node-001',
    region: 'us-west-2',
    availableResources: {
      cpuPercent: 40,
      memoryMB: 512,
      diskGB: 10,
    },
    networkQuality: 'low',
  },
});

console.log('Processed Locally:', result.processedLocally);
console.log('Latency:', result.latency, 'ms');
```

### Governance - Compliance Checking

```typescript
const governanceClient = new GovernanceLLMClient(config);

// Validate compliance
const complianceResult = await governanceClient.validateCompliance({
  requestId: 'comp-req-001',
  action: 'process_user_data',
  context: {
    userId: 'user-456',
    tenantId: 'tenant-789',
    environment: 'production',
    dataClassification: 'PII',
  },
  policies: ['gdpr', 'hipaa', 'internal-data-policy'],
});

if (!complianceResult.compliant) {
  console.error('Violations:', complianceResult.violations);
  throw new Error('Compliance check failed');
}
```

---

## Error Handling

### Error Types

```typescript
enum LLMErrorType {
  // Retryable (automatic retry)
  RATE_LIMIT,          // 429 errors
  TIMEOUT,             // Request timeout
  SERVICE_UNAVAILABLE, // 5xx errors
  NETWORK_ERROR,       // Connection issues

  // Non-retryable (immediate failure)
  AUTHENTICATION_ERROR, // Invalid API key
  INVALID_REQUEST,      // Bad request
  CONTENT_FILTER,       // Content policy violation
  MODEL_NOT_FOUND,      // Model doesn't exist
  QUOTA_EXCEEDED,       // Account quota exceeded

  // Circuit breaker
  CIRCUIT_OPEN,        // Circuit breaker open

  // Unknown
  UNKNOWN_ERROR,       // Unexpected error
}
```

### Error Handling Pattern

```typescript
try {
  const analysis = await client.analyzeAnomaly(event);
  // Success path
} catch (error) {
  if (error instanceof LLMError) {
    if (error.retryable) {
      // Retry is handled automatically by RetryManager
      logger.warn('Retryable error', { type: error.type });
    } else {
      // Non-retryable - take action
      logger.error('Non-retryable error', { type: error.type });
      await sendAlert(error);
    }
  } else {
    // Unknown error
    logger.error('Unknown error', { error });
  }
}
```

---

## Resilience Patterns

### Retry Configuration

```typescript
{
  "retry": {
    "enabled": true,
    "maxAttempts": 3,           // Try up to 3 times
    "baseDelayMs": 1000,        // Start with 1s delay
    "maxDelayMs": 30000,        // Max 30s delay
    "backoffMultiplier": 2,     // Exponential: 1s, 2s, 4s...
    "jitterMs": 100,            // Add random jitter
    "retryableErrors": [        // Which errors to retry
      "RATE_LIMIT",
      "TIMEOUT",
      "SERVICE_UNAVAILABLE"
    ]
  }
}
```

**Retry Timeline**:
```
Attempt 1: Immediate
Attempt 2: 1s + jitter (100ms)
Attempt 3: 2s + jitter (100ms)
Attempt 4: 4s + jitter (100ms)
```

### Circuit Breaker Configuration

```typescript
{
  "circuitBreaker": {
    "enabled": true,
    "failureThreshold": 5,      // Open after 5 failures
    "successThreshold": 2,      // Close after 2 successes
    "timeout": 60000,           // Wait 60s before half-open
    "halfOpenMaxAttempts": 1,   // 1 request in half-open
    "volumeThreshold": 10       // Need 10 requests before opening
  }
}
```

**Circuit States**:
```
CLOSED → (5 failures) → OPEN → (60s timeout) → HALF_OPEN → (2 successes) → CLOSED
                                                    ↓
                                              (1 failure)
                                                    ↓
                                                  OPEN
```

### Rate Limiting Configuration

```typescript
{
  "rateLimit": {
    "enabled": true,
    "requestsPerMinute": 50,    // Max 50 req/min
    "requestsPerHour": 2000,    // Max 2000 req/hour
    "tokensPerMinute": 100000,  // Max 100K tokens/min
    "tokensPerDay": 5000000,    // Max 5M tokens/day
    "burstAllowance": 10        // Allow bursts of 10
  }
}
```

**Rate Limit Behavior**:
- Requests are throttled automatically
- Burst allowance allows temporary spikes
- Client waits when limits reached
- No errors thrown (transparent backpressure)

---

## Observability

### Logging Levels

```typescript
// Debug: Detailed information for diagnostics
logger.debug('Detailed request info', { /* ... */ });

// Info: General informational messages
logger.info('Request completed', { requestId, duration });

// Warn: Warning messages, potential issues
logger.warn('Retrying request', { attempt, errorType });

// Error: Error conditions
logger.error('Request failed', { error, requestId });
```

### Key Metrics

```typescript
// Request metrics
'llm_client.requests.total'           // Counter
'llm_client.request.duration_ms'      // Histogram
'llm_client.errors.total'             // Counter

// Token usage
'llm_client.tokens.prompt'            // Histogram
'llm_client.tokens.completion'        // Histogram
'llm_client.tokens.total'             // Histogram
'llm_client.cost.estimated'           // Histogram

// Resilience
'llm_client.retry.attempts'           // Counter
'llm_client.circuit_breaker.state'    // Gauge (0=closed, 1=half-open, 2=open)
'llm_client.rate_limit.wait_ms'       // Histogram
```

### Health Check

```typescript
const health = client.getHealthStatus();

console.log({
  clientId: health.clientId,
  provider: health.provider,
  circuitBreakerState: health.circuitBreakerState,
  circuitBreakerStats: {
    failureCount: health.circuitBreakerStats.failureCount,
    successCount: health.circuitBreakerStats.successCount,
  },
  rateLimiterStats: {
    requestsAvailable: health.rateLimiterStats.requestBucket.tokens,
    tokensAvailable: health.rateLimiterStats.tokenBucket.tokens,
  },
});
```

---

## Performance Optimization

### Enable Caching

```typescript
{
  "features": {
    "cachingEnabled": true
  }
}

// Identical requests will be served from cache
// Cache TTL: 1 hour (configurable)
```

### Choose Right Model

```typescript
// Simple tasks → Faster, cheaper models
const quickAnalysis = await client.classifySeverity(metrics);
// Use: gpt-3.5-turbo, claude-instant

// Complex tasks → More capable models
const deepAnalysis = await client.analyzeAnomaly(event);
// Use: gpt-4, claude-3-opus
```

### Optimize Prompts

```typescript
// Bad: Verbose, repetitive
const badPrompt = `
Please analyze this anomaly event and tell me if it's a real anomaly...
[5000 characters]
`;

// Good: Concise, structured
const goodPrompt = `
Analyze anomaly. Respond JSON:
{ "isAnomaly": bool, "severity": "P0-P4", "recommendations": [] }

Event: ${JSON.stringify(event)}
`;
```

### Batch Processing

```typescript
// Process multiple items efficiently
const events = [...]; // Array of events

// Bad: Sequential
for (const event of events) {
  await client.analyzeAnomaly(event); // Slow!
}

// Good: Parallel with batching
const batchSize = 10;
for (let i = 0; i < events.length; i += batchSize) {
  const batch = events.slice(i, i + batchSize);
  await Promise.all(
    batch.map(event => client.analyzeAnomaly(event))
  );
}
```

---

## Testing

### Unit Testing with Mocks

```typescript
import { MockLLMProvider } from '../test-utils/MockLLMProvider';

describe('SentinelLLMClient', () => {
  let client: SentinelLLMClient;
  let mockProvider: MockLLMProvider;

  beforeEach(() => {
    mockProvider = new MockLLMProvider();
    client = new SentinelLLMClient(config, mockProvider, logger, metrics);
  });

  it('should analyze anomaly', async () => {
    // Setup mock response
    mockProvider.setResponse('test-id', {
      id: 'response-1',
      requestId: 'test-id',
      timestamp: new Date().toISOString(),
      model: 'gpt-4',
      content: JSON.stringify({
        isAnomaly: true,
        confidence: 0.95,
        severity: 'P1',
      }),
      role: 'assistant',
      finishReason: 'stop',
      usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
    });

    const analysis = await client.analyzeAnomaly(event);

    expect(analysis.isAnomaly).toBe(true);
    expect(analysis.severity).toBe('P1');
  });
});
```

### Integration Testing

```typescript
describe('Integration Test', () => {
  it('should work with real provider', async () => {
    const config = ConfigLoader.load('test');
    const client = new SentinelLLMClient(config);

    const analysis = await client.analyzeAnomaly(testEvent);

    expect(analysis).toBeDefined();
    expect(analysis.isAnomaly).toBeDefined();
  }, 30000); // 30s timeout
});
```

---

## Troubleshooting

### Issue: High Error Rate

**Symptoms**: Error rate > 1%, circuit breaker opening

**Check**:
```typescript
const health = client.getHealthStatus();
console.log('Circuit State:', health.circuitBreakerState);
console.log('Failure Count:', health.circuitBreakerStats.failureCount);
```

**Fix**:
1. Verify API key is valid
2. Check provider service status
3. Review rate limit configuration
4. Increase retry delays

### Issue: Slow Responses

**Symptoms**: p95 latency > 5s, timeout errors

**Check**:
```typescript
const stats = client.rateLimiter.getStats();
console.log('Waiting for rate limits:', stats);
```

**Fix**:
1. Increase rate limits (if under quota)
2. Enable caching
3. Use smaller models
4. Reduce concurrent requests

### Issue: High Costs

**Symptoms**: Unexpected API costs

**Check**:
```typescript
// Monitor token usage
metrics.getMetric('llm_client.tokens.total');
metrics.getMetric('llm_client.cost.estimated');
```

**Fix**:
1. Use cheaper models for simple tasks
2. Enable caching
3. Optimize prompts (reduce tokens)
4. Set daily token limits

---

## Common Patterns

### Multi-Provider Fallback

```typescript
const primaryClient = new SentinelLLMClient(openAIConfig);
const fallbackClient = new SentinelLLMClient(anthropicConfig);

async function analyzeWithFallback(event: AnomalyEvent) {
  try {
    return await primaryClient.analyzeAnomaly(event);
  } catch (error) {
    logger.warn('Primary provider failed, trying fallback');
    return await fallbackClient.analyzeAnomaly(event);
  }
}
```

### Streaming Responses

```typescript
async function streamAnalysis(event: AnomalyEvent) {
  console.log('Starting analysis...\n');

  for await (const chunk of client.streamResponse(request)) {
    process.stdout.write(chunk.delta.content || '');

    if (chunk.finishReason) {
      console.log(`\n\nFinished: ${chunk.finishReason}`);
    }
  }
}
```

### Custom Middleware

```typescript
class CustomLoggingMiddleware implements IMiddleware {
  readonly name = 'custom-logging';
  readonly priority = 10;

  async onRequest(request: LLMRequest, context: RequestContext) {
    console.log('Request:', request.id);
    return request;
  }

  async onResponse(response: LLMResponse, context: RequestContext) {
    console.log('Response:', response.id);
    return response;
  }

  async onError(error: Error, context: RequestContext) {
    console.error('Error:', error.message);
  }
}

client.use(new CustomLoggingMiddleware());
```

---

## Configuration Templates

### Development

```json
{
  "clientId": "dev-client",
  "environment": "development",
  "provider": {
    "provider": "openai",
    "defaultModel": "gpt-3.5-turbo"
  },
  "resilience": {
    "retry": { "enabled": true, "maxAttempts": 2 },
    "circuitBreaker": { "enabled": false },
    "rateLimit": { "enabled": false }
  },
  "observability": {
    "logging": { "level": "debug", "redactPII": false }
  }
}
```

### Production

```json
{
  "clientId": "prod-client",
  "environment": "production",
  "provider": {
    "provider": "anthropic",
    "defaultModel": "claude-3-5-sonnet-20241022"
  },
  "resilience": {
    "retry": { "enabled": true, "maxAttempts": 3 },
    "circuitBreaker": { "enabled": true, "failureThreshold": 5 },
    "rateLimit": { "enabled": true, "requestsPerMinute": 50 }
  },
  "observability": {
    "logging": { "level": "info", "redactPII": true },
    "metrics": { "enabled": true },
    "tracing": { "enabled": true },
    "auditing": { "enabled": true }
  }
}
```

---

## API Reference

### BaseLLMClient

```typescript
abstract class BaseLLMClient {
  // Execute LLM request
  protected executeRequest(request: LLMRequest): Promise<LLMResponse>

  // Health status
  getHealthStatus(): HealthStatus

  // Client name
  get name(): string
}
```

### SentinelLLMClient

```typescript
class SentinelLLMClient extends BaseLLMClient {
  // Analyze anomaly event
  analyzeAnomaly(event: AnomalyEvent): Promise<AnomalyAnalysis>

  // Classify severity
  classifySeverity(metrics: MetricData): Promise<SeverityClassification>

  // Generate insights
  generateInsights(incidents: Incident[]): Promise<Insight[]>

  // Predict impact
  predictImpact(anomaly: Anomaly): Promise<ImpactPrediction>
}
```

### ShieldLLMClient

```typescript
class ShieldLLMClient extends BaseLLMClient {
  // Analyze security threat
  analyzeThreat(event: SecurityEvent): Promise<ThreatAnalysis>

  // Assess risk
  assessRisk(vulnerability: Vulnerability): Promise<RiskAssessment>

  // Detect malicious patterns
  detectMaliciousPatterns(data: string): Promise<MaliciousPattern[]>

  // Generate mitigation plan
  generateMitigationSteps(threat: Threat): Promise<MitigationPlan>
}
```

### EdgeAgentLLMClient

```typescript
class EdgeAgentLLMClient extends BaseLLMClient {
  // Process local inference
  processLocalInference(request: InferenceRequest): Promise<InferenceResult>

  // Sync with central hub
  syncWithCentralHub(data: EdgeData): Promise<SyncResult>

  // Handle offline request
  handleOfflineRequest(request: LLMRequest): Promise<QueuedRequest>

  // Prioritize requests
  prioritizeRequest(requests: LLMRequest[]): Promise<LLMRequest[]>
}
```

### GovernanceLLMClient

```typescript
class GovernanceLLMClient extends BaseLLMClient {
  // Validate compliance
  validateCompliance(request: ComplianceRequest): Promise<ComplianceResult>

  // Check policy
  checkPolicy(action: Action, policy: Policy): Promise<PolicyViolation[]>

  // Audit request
  auditRequest(request: AuditRequest): Promise<AuditReport>

  // Generate compliance report
  generateComplianceReport(incidents: Incident[]): Promise<ComplianceReport>
}
```

---

## Resources

- **Architecture**: [LLM_CLIENT_ARCHITECTURE.md](./LLM_CLIENT_ARCHITECTURE.md)
- **Implementation**: [LLM_CLIENT_IMPLEMENTATION_GUIDE.md](./LLM_CLIENT_IMPLEMENTATION_GUIDE.md)
- **Types**: [llm-client-types.ts](./llm-client-types.ts)
- **OpenAI Docs**: https://platform.openai.com/docs
- **Anthropic Docs**: https://docs.anthropic.com
- **Main Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)

---

**Last Updated**: 2025-11-12
