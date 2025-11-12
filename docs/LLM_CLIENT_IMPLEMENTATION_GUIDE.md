# LLM Client Implementation Guide

**Version**: 1.0.0
**Date**: 2025-11-12
**Target Audience**: Implementation Team

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Implementation Phases](#2-implementation-phases)
3. [Code Examples](#3-code-examples)
4. [Best Practices](#4-best-practices)
5. [Testing Guidelines](#5-testing-guidelines)
6. [Deployment Checklist](#6-deployment-checklist)
7. [Troubleshooting](#7-troubleshooting)
8. [Performance Tuning](#8-performance-tuning)

---

## 1. Quick Start

### 1.1 Prerequisites

```bash
# Install dependencies
npm install openai anthropic zod winston pino

# Install type definitions
npm install -D @types/node @types/jest

# Install development tools
npm install -D typescript ts-node jest ts-jest
```

### 1.2 Project Structure Setup

```bash
mkdir -p src/llm-clients/{base,sentinel,shield,edge-agent,governance}
mkdir -p src/llm-clients/{providers,resilience,observability,middleware}
mkdir -p config/{production,staging,development}
mkdir -p tests/{unit,integration,load}
```

### 1.3 Basic Configuration

Create `config/development.json`:

```json
{
  "clientId": "sentinel-llm-dev",
  "clientName": "Sentinel LLM Client",
  "version": "1.0.0",
  "provider": {
    "provider": "openai",
    "apiKey": "${OPENAI_API_KEY}",
    "defaultModel": "gpt-4",
    "availableModels": ["gpt-4", "gpt-3.5-turbo"],
    "defaultTemperature": 0.7,
    "defaultMaxTokens": 2048,
    "defaultTopP": 1.0
  },
  "resilience": {
    "retry": {
      "enabled": true,
      "maxAttempts": 3,
      "baseDelayMs": 1000,
      "maxDelayMs": 30000,
      "backoffMultiplier": 2,
      "jitterMs": 100,
      "retryableErrors": ["RATE_LIMIT", "TIMEOUT", "SERVICE_UNAVAILABLE"]
    },
    "circuitBreaker": {
      "enabled": true,
      "failureThreshold": 5,
      "successThreshold": 2,
      "timeout": 60000,
      "halfOpenMaxAttempts": 1,
      "volumeThreshold": 10
    },
    "rateLimit": {
      "enabled": true,
      "requestsPerMinute": 50,
      "requestsPerHour": 2000,
      "tokensPerMinute": 100000,
      "tokensPerDay": 5000000,
      "burstAllowance": 10
    },
    "timeout": {
      "requestTimeoutMs": 30000,
      "connectionTimeoutMs": 5000,
      "streamTimeoutMs": 120000
    }
  },
  "observability": {
    "logging": {
      "enabled": true,
      "level": "debug",
      "logRequests": true,
      "logResponses": true,
      "redactPII": false,
      "redactApiKeys": true,
      "maxBodyLength": 50000
    },
    "metrics": {
      "enabled": true,
      "prefix": "llm_client.sentinel",
      "labels": {
        "environment": "development",
        "client": "sentinel"
      },
      "exportInterval": 60000
    },
    "tracing": {
      "enabled": false,
      "serviceName": "sentinel-llm-client",
      "samplingRate": 1.0
    },
    "auditing": {
      "enabled": false,
      "logAllRequests": false,
      "logFailedRequests": true,
      "retentionDays": 7,
      "storageBackend": "file"
    }
  },
  "features": {
    "streamingEnabled": true,
    "functionCallingEnabled": true,
    "cachingEnabled": false,
    "embeddingsEnabled": false,
    "visionEnabled": false
  },
  "environment": "development"
}
```

---

## 2. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

**Priority**: P0

**Deliverables**:
1. Base LLM Client abstract class
2. Provider interface and factory
3. Configuration loader
4. Error handling framework
5. Basic logging

**Implementation Order**:
```
1. src/llm-clients/base/types.ts
2. src/llm-clients/errors/LLMError.ts
3. src/llm-clients/config/ConfigLoader.ts
4. src/llm-clients/providers/ILLMProvider.ts
5. src/llm-clients/base/BaseLLMClient.ts
```

### Phase 2: Provider Implementations (Week 2-3)

**Priority**: P0

**Deliverables**:
1. OpenAI provider
2. Anthropic provider
3. Provider factory
4. Provider-specific error mapping

**Implementation Order**:
```
1. src/llm-clients/providers/OpenAIProvider.ts
2. src/llm-clients/providers/AnthropicProvider.ts
3. src/llm-clients/providers/ProviderFactory.ts
4. tests/unit/providers/*.test.ts
```

### Phase 3: Resilience Layer (Week 3-4)

**Priority**: P0

**Deliverables**:
1. Retry manager with exponential backoff
2. Circuit breaker
3. Rate limiter
4. Timeout manager

**Implementation Order**:
```
1. src/llm-clients/resilience/RetryManager.ts
2. src/llm-clients/resilience/CircuitBreaker.ts
3. src/llm-clients/resilience/RateLimiter.ts
4. src/llm-clients/resilience/TimeoutManager.ts
5. tests/unit/resilience/*.test.ts
```

### Phase 4: Observability (Week 4-5)

**Priority**: P1

**Deliverables**:
1. Structured logger with PII redaction
2. Metrics collector
3. Distributed tracing
4. Audit logger

**Implementation Order**:
```
1. src/llm-clients/observability/Logger.ts
2. src/llm-clients/observability/Metrics.ts
3. src/llm-clients/observability/Tracer.ts
4. src/llm-clients/observability/AuditLogger.ts
```

### Phase 5: Specialized Clients (Week 5-7)

**Priority**: P0 for Sentinel/Shield, P1 for Edge/Governance

**Deliverables**:
1. Sentinel LLM Client
2. Shield LLM Client
3. Edge-Agent LLM Client
4. Governance LLM Client

**Implementation Order**:
```
1. src/llm-clients/sentinel/SentinelLLMClient.ts
2. src/llm-clients/shield/ShieldLLMClient.ts
3. src/llm-clients/edge-agent/EdgeAgentLLMClient.ts
4. src/llm-clients/governance/GovernanceLLMClient.ts
```

### Phase 6: Testing & Optimization (Week 7-8)

**Priority**: P0

**Deliverables**:
1. Unit tests (>80% coverage)
2. Integration tests
3. Load tests
4. Performance optimizations

---

## 3. Code Examples

### 3.1 Base LLM Client Implementation

**File**: `src/llm-clients/base/BaseLLMClient.ts`

```typescript
import { LLMClientConfig, LLMRequest, LLMResponse, ValidationResult } from '../types';
import { ILLMProvider } from '../providers/ILLMProvider';
import { RetryManager } from '../resilience/RetryManager';
import { CircuitBreaker } from '../resilience/CircuitBreaker';
import { RateLimiter } from '../resilience/RateLimiter';
import { TimeoutManager } from '../resilience/TimeoutManager';
import { LLMClientLogger } from '../observability/Logger';
import { LLMClientMetrics } from '../observability/Metrics';
import { LLMError, LLMErrorType } from '../errors/LLMError';
import { RequestContext } from './RequestContext';

/**
 * Abstract base class for all LLM clients
 * Provides common functionality and enforces interface contracts
 */
export abstract class BaseLLMClient {
  protected config: LLMClientConfig;
  protected provider: ILLMProvider;
  protected retryManager: RetryManager;
  protected circuitBreaker: CircuitBreaker;
  protected rateLimiter: RateLimiter;
  protected timeoutManager: TimeoutManager;
  protected logger: LLMClientLogger;
  protected metrics: LLMClientMetrics;

  constructor(
    config: LLMClientConfig,
    provider: ILLMProvider,
    logger: LLMClientLogger,
    metrics: LLMClientMetrics
  ) {
    this.config = config;
    this.provider = provider;
    this.logger = logger;
    this.metrics = metrics;

    // Initialize resilience components
    this.retryManager = new RetryManager(
      config.resilience.retry,
      logger,
      metrics
    );

    this.circuitBreaker = new CircuitBreaker(
      config.resilience.circuitBreaker,
      logger,
      metrics
    );

    this.rateLimiter = new RateLimiter(
      config.resilience.rateLimit,
      logger,
      metrics
    );

    this.timeoutManager = new TimeoutManager(
      config.resilience.timeout,
      logger
    );
  }

  /**
   * Abstract methods - must be implemented by subclasses
   */
  abstract validateRequest(request: LLMRequest): ValidationResult;
  abstract formatPrompt(context: any): string;
  abstract parseResponse(response: LLMResponse): any;

  /**
   * Execute LLM request with full resilience stack
   */
  protected async executeRequest(request: LLMRequest): Promise<LLMResponse> {
    const context: RequestContext = {
      requestId: request.id,
      retryCount: 0,
      startTime: Date.now(),
      config: this.config,
      metadata: request.metadata || {},
    };

    // Validate request
    const validation = this.validateRequest(request);
    if (!validation.valid) {
      throw new LLMError(
        LLMErrorType.INVALID_REQUEST,
        `Request validation failed: ${validation.errors.join(', ')}`,
        400,
        false
      );
    }

    // Log request
    this.logger.logRequest(request);
    this.metrics.recordRequest(request);

    try {
      // Execute with retry and circuit breaker
      const response = await this.retryManager.executeWithRetry(
        async () => {
          return await this.circuitBreaker.execute(async () => {
            return await this.executeWithRateLimit(request, context);
          });
        },
        context
      );

      // Log response
      const duration = Date.now() - context.startTime;
      this.logger.logResponse(response, duration);
      this.metrics.recordResponse(response, duration, true);

      return response;
    } catch (error) {
      // Log error
      const duration = Date.now() - context.startTime;
      const llmError = error as LLMError;
      this.logger.error('LLM request failed', {
        requestId: request.id,
        errorType: llmError.type,
        message: llmError.message,
        duration,
      });
      this.metrics.recordError(llmError, duration);

      throw error;
    }
  }

  /**
   * Execute request with rate limiting and timeout
   */
  private async executeWithRateLimit(
    request: LLMRequest,
    context: RequestContext
  ): Promise<LLMResponse> {
    // Apply rate limiting
    await this.rateLimiter.acquire(request.maxTokens || 1000);

    // Execute with timeout
    const timeout = this.timeoutManager.getRequestTimeout(false);
    const response = await this.timeoutManager.executeWithTimeout(
      async () => {
        return await this.provider.complete({
          id: request.id,
          model: request.model,
          messages: request.messages,
          temperature: request.temperature,
          maxTokens: request.maxTokens,
          topP: request.topP,
          frequencyPenalty: request.frequencyPenalty,
          presencePenalty: request.presencePenalty,
          stopSequences: request.stopSequences,
        });
      },
      timeout,
      context
    );

    // Record actual token usage
    this.rateLimiter.recordActualUsage(response.usage.totalTokens);

    return response;
  }

  /**
   * Get client name for logging
   */
  get name(): string {
    return this.config.clientName;
  }

  /**
   * Get client health status
   */
  getHealthStatus() {
    return {
      clientId: this.config.clientId,
      clientName: this.config.clientName,
      provider: this.config.provider.provider,
      circuitBreakerState: this.circuitBreaker.getState(),
      circuitBreakerStats: this.circuitBreaker.getStats(),
      rateLimiterStats: this.rateLimiter.getStats(),
    };
  }
}
```

### 3.2 Sentinel LLM Client Implementation

**File**: `src/llm-clients/sentinel/SentinelLLMClient.ts`

```typescript
import { BaseLLMClient } from '../base/BaseLLMClient';
import {
  SentinelLLMConfig,
  AnomalyEvent,
  AnomalyAnalysis,
  SeverityClassification,
  LLMRequest,
  LLMResponse,
  ValidationResult,
} from '../types';
import { LLMError, LLMErrorType } from '../errors/LLMError';
import { SentinelPrompts } from './prompts';

/**
 * Sentinel LLM Client - Anomaly Detection & Monitoring
 */
export class SentinelLLMClient extends BaseLLMClient {
  private prompts: SentinelPrompts;

  constructor(
    config: SentinelLLMConfig,
    provider: ILLMProvider,
    logger: LLMClientLogger,
    metrics: LLMClientMetrics
  ) {
    super(config, provider, logger, metrics);
    this.prompts = new SentinelPrompts();
  }

  /**
   * Analyze anomaly event
   */
  async analyzeAnomaly(event: AnomalyEvent): Promise<AnomalyAnalysis> {
    this.logger.info('Analyzing anomaly', {
      eventId: event.eventId,
      source: event.source,
    });

    // Create LLM request
    const request: LLMRequest = {
      id: `anomaly-analysis-${event.eventId}`,
      timestamp: new Date().toISOString(),
      model: this.config.provider.defaultModel,
      messages: [
        {
          role: 'system',
          content: this.prompts.getAnomalyAnalysisSystemPrompt(),
        },
        {
          role: 'user',
          content: this.formatPrompt(event),
        },
      ],
      temperature: 0.3, // Lower temperature for more deterministic analysis
      maxTokens: 2048,
      metadata: {
        eventId: event.eventId,
        source: event.source,
      },
    };

    // Execute request
    const response = await this.executeRequest(request);

    // Parse and return analysis
    return this.parseResponse(response);
  }

  /**
   * Classify severity of metrics
   */
  async classifySeverity(metrics: MetricData): Promise<SeverityClassification> {
    const request: LLMRequest = {
      id: `severity-classification-${Date.now()}`,
      timestamp: new Date().toISOString(),
      model: this.config.provider.defaultModel,
      messages: [
        {
          role: 'system',
          content: this.prompts.getSeverityClassificationSystemPrompt(),
        },
        {
          role: 'user',
          content: JSON.stringify(metrics, null, 2),
        },
      ],
      temperature: 0.2,
      maxTokens: 1024,
    };

    const response = await this.executeRequest(request);
    return JSON.parse(response.content);
  }

  /**
   * Validate request
   */
  validateRequest(request: LLMRequest): ValidationResult {
    const errors: string[] = [];

    if (!request.id) {
      errors.push('Request ID is required');
    }

    if (!request.model) {
      errors.push('Model is required');
    }

    if (!request.messages || request.messages.length === 0) {
      errors.push('At least one message is required');
    }

    if (request.temperature !== undefined) {
      if (request.temperature < 0 || request.temperature > 2) {
        errors.push('Temperature must be between 0 and 2');
      }
    }

    if (request.maxTokens !== undefined) {
      if (request.maxTokens < 1 || request.maxTokens > 8192) {
        errors.push('Max tokens must be between 1 and 8192');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Format prompt for anomaly analysis
   */
  formatPrompt(event: AnomalyEvent): string {
    return `
Analyze the following anomaly event:

Event ID: ${event.eventId}
Source: ${event.source}
Timestamp: ${event.timestamp}

Metrics:
${JSON.stringify(event.metrics, null, 2)}

Context:
${JSON.stringify(event.context, null, 2)}

Please analyze this event and provide:
1. Whether this is a genuine anomaly (true/false)
2. Confidence level (0-1)
3. Severity classification (P0-P4)
4. Root cause analysis
5. Recommended actions

Respond in JSON format.
    `.trim();
  }

  /**
   * Parse response into AnomalyAnalysis
   */
  parseResponse(response: LLMResponse): AnomalyAnalysis {
    try {
      const parsed = JSON.parse(response.content);

      // Validate parsed response
      if (typeof parsed.isAnomaly !== 'boolean') {
        throw new Error('Invalid isAnomaly field');
      }

      if (
        typeof parsed.confidence !== 'number' ||
        parsed.confidence < 0 ||
        parsed.confidence > 1
      ) {
        throw new Error('Invalid confidence field');
      }

      if (!['P0', 'P1', 'P2', 'P3', 'P4'].includes(parsed.severity)) {
        throw new Error('Invalid severity field');
      }

      return {
        isAnomaly: parsed.isAnomaly,
        confidence: parsed.confidence,
        severity: parsed.severity,
        rootCause: parsed.rootCause,
        recommendations: parsed.recommendations || [],
        relatedIncidents: parsed.relatedIncidents || [],
      };
    } catch (error) {
      this.logger.error('Failed to parse response', {
        error: (error as Error).message,
        responseContent: response.content,
      });

      throw new LLMError(
        LLMErrorType.INVALID_REQUEST,
        `Failed to parse LLM response: ${(error as Error).message}`,
        undefined,
        false,
        { responseContent: response.content }
      );
    }
  }
}
```

### 3.3 Prompt Template System

**File**: `src/llm-clients/sentinel/prompts.ts`

```typescript
/**
 * Sentinel LLM Client Prompts
 */
export class SentinelPrompts {
  /**
   * System prompt for anomaly analysis
   */
  getAnomalyAnalysisSystemPrompt(): string {
    return `
You are an expert AI system for analyzing anomalies in distributed systems.
Your role is to analyze metrics, logs, and events to determine if they represent
genuine anomalies that require attention.

Guidelines:
- Be precise and data-driven in your analysis
- Consider historical patterns and baselines
- Classify severity based on business impact
- Provide actionable recommendations
- Use structured JSON output

Severity Levels:
- P0: Critical - Immediate action required, system down or major data loss
- P1: High - Significant degradation, customer-facing impact
- P2: Medium - Performance degradation, limited impact
- P3: Low - Minor issues, monitoring recommended
- P4: Info - Informational, no action needed

Always respond with valid JSON in this format:
{
  "isAnomaly": boolean,
  "confidence": number (0-1),
  "severity": "P0" | "P1" | "P2" | "P3" | "P4",
  "rootCause": string,
  "recommendations": string[],
  "relatedIncidents": string[]
}
    `.trim();
  }

  /**
   * System prompt for severity classification
   */
  getSeverityClassificationSystemPrompt(): string {
    return `
You are a severity classification expert for incident management systems.
Analyze the provided metrics and classify the severity level.

Respond with valid JSON in this format:
{
  "severity": "P0" | "P1" | "P2" | "P3" | "P4",
  "confidence": number (0-1),
  "reasoning": string,
  "factors": string[]
}
    `.trim();
  }

  /**
   * User prompt for impact prediction
   */
  getImpactPredictionPrompt(anomaly: any): string {
    return `
Predict the potential impact of this anomaly:

${JSON.stringify(anomaly, null, 2)}

Analyze:
1. Likelihood of escalation (0-1)
2. Expected severity if escalates
3. Time to critical impact (minutes)
4. Affected services/resources
5. Mitigation options

Respond in JSON format.
    `.trim();
  }
}
```

### 3.4 Provider Implementation - OpenAI

**File**: `src/llm-clients/providers/OpenAIProvider.ts`

```typescript
import OpenAI from 'openai';
import {
  ILLMProvider,
  CompletionRequest,
  CompletionResponse,
  CompletionChunk,
  ProviderCapabilities,
  ModelInfo,
  CostEstimate,
} from '../types';
import { RateLimiter } from '../resilience/RateLimiter';
import { LLMError, LLMErrorType } from '../errors/LLMError';

/**
 * OpenAI Provider Implementation
 */
export class OpenAIProvider implements ILLMProvider {
  readonly name = 'openai';
  readonly version = '1.0.0';
  readonly capabilities: ProviderCapabilities = {
    streaming: true,
    functionCalling: true,
    vision: true,
    embeddings: true,
    jsonMode: true,
    maxTokens: 4096,
    maxContextWindow: 128000,
  };

  private client: OpenAI;
  private rateLimiter: RateLimiter;
  private config: OpenAIConfig;

  constructor(config: OpenAIConfig, rateLimiter: RateLimiter) {
    this.config = config;
    this.rateLimiter = rateLimiter;

    this.client = new OpenAI({
      apiKey: config.apiKey,
      organization: config.organization,
      baseURL: config.baseUrl,
    });
  }

  /**
   * Complete chat request
   */
  async complete(request: CompletionRequest): Promise<CompletionResponse> {
    try {
      const openAIRequest = this.transformRequest(request);
      const response = await this.client.chat.completions.create(openAIRequest);

      return this.transformResponse(response, request.id);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Stream chat completion
   */
  async *stream(
    request: CompletionRequest
  ): AsyncIterableIterator<CompletionChunk> {
    try {
      const openAIRequest = {
        ...this.transformRequest(request),
        stream: true,
      };

      const stream = await this.client.chat.completions.create(openAIRequest);

      for await (const chunk of stream) {
        yield this.transformChunk(chunk);
      }
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get embeddings
   */
  async embeddings(request: EmbeddingRequest): Promise<EmbeddingResponse> {
    try {
      const response = await this.client.embeddings.create({
        model: request.model,
        input: request.input,
      });

      return {
        embeddings: response.data.map(d => d.embedding),
        usage: {
          promptTokens: response.usage.prompt_tokens,
          totalTokens: response.usage.total_tokens,
        },
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate API key
   */
  async validateApiKey(): Promise<boolean> {
    try {
      await this.client.models.list();
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get available models
   */
  async getModels(): Promise<ModelInfo[]> {
    try {
      const models = await this.client.models.list();
      return models.data.map(m => ({
        id: m.id,
        name: m.id,
        description: `OpenAI ${m.id}`,
        contextWindow: this.getContextWindow(m.id),
        maxOutputTokens: 4096,
        supportsVision: m.id.includes('vision') || m.id.includes('gpt-4'),
        supportsFunctions: true,
      }));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Estimate cost
   */
  estimateCost(request: CompletionRequest): CostEstimate {
    // Rough token estimation
    const promptTokens = this.estimateTokens(
      JSON.stringify(request.messages)
    );
    const completionTokens = request.maxTokens || 1000;

    const pricing = this.getPricing(request.model);

    const promptCost = (promptTokens / 1000) * pricing.prompt;
    const completionCost = (completionTokens / 1000) * pricing.completion;

    return {
      estimatedCost: promptCost + completionCost,
      currency: 'USD',
      breakdown: {
        promptCost,
        completionCost,
      },
    };
  }

  /**
   * Transform generic request to OpenAI format
   */
  private transformRequest(request: CompletionRequest): any {
    return {
      model: request.model,
      messages: request.messages.map(m => ({
        role: m.role,
        content: typeof m.content === 'string' ? m.content : this.transformContent(m.content),
        name: m.name,
        function_call: m.functionCall,
      })),
      temperature: request.temperature,
      max_tokens: request.maxTokens,
      top_p: request.topP,
      frequency_penalty: request.frequencyPenalty,
      presence_penalty: request.presencePenalty,
      stop: request.stopSequences,
      functions: request.functions?.map(f => ({
        name: f.name,
        description: f.description,
        parameters: f.parameters,
      })),
    };
  }

  /**
   * Transform content blocks
   */
  private transformContent(content: ContentBlock[]): any[] {
    return content.map(block => {
      if (block.type === 'text') {
        return { type: 'text', text: block.text };
      } else if (block.type === 'image') {
        return {
          type: 'image_url',
          image_url: {
            url: block.source.type === 'url'
              ? block.source.data
              : `data:image/jpeg;base64,${block.source.data}`,
          },
        };
      }
      return block;
    });
  }

  /**
   * Transform OpenAI response to generic format
   */
  private transformResponse(response: any, requestId: string): CompletionResponse {
    const choice = response.choices[0];

    return {
      id: response.id,
      requestId,
      timestamp: new Date().toISOString(),
      model: response.model,
      content: choice.message.content || '',
      role: 'assistant',
      functionCall: choice.message.function_call
        ? {
            name: choice.message.function_call.name,
            arguments: JSON.parse(choice.message.function_call.arguments),
          }
        : undefined,
      finishReason: this.mapFinishReason(choice.finish_reason),
      usage: {
        promptTokens: response.usage.prompt_tokens,
        completionTokens: response.usage.completion_tokens,
        totalTokens: response.usage.total_tokens,
        estimatedCost: this.calculateCost(
          response.model,
          response.usage.prompt_tokens,
          response.usage.completion_tokens
        ),
      },
    };
  }

  /**
   * Transform streaming chunk
   */
  private transformChunk(chunk: any): CompletionChunk {
    const delta = chunk.choices[0]?.delta || {};

    return {
      id: chunk.id,
      delta: {
        role: delta.role,
        content: delta.content,
        functionCall: delta.function_call
          ? {
              name: delta.function_call.name,
              arguments: delta.function_call.arguments,
            }
          : undefined,
      },
      finishReason: chunk.choices[0]?.finish_reason,
    };
  }

  /**
   * Handle provider-specific errors
   */
  private handleError(error: any): LLMError {
    const statusCode = error.status || error.statusCode;

    switch (statusCode) {
      case 429:
        return new LLMError(
          LLMErrorType.RATE_LIMIT,
          'OpenAI rate limit exceeded',
          429,
          true,
          { retryAfter: error.headers?.['retry-after'] }
        );

      case 401:
      case 403:
        return new LLMError(
          LLMErrorType.AUTHENTICATION_ERROR,
          'OpenAI authentication failed',
          statusCode,
          false
        );

      case 400:
        if (error.message?.includes('content_filter')) {
          return new LLMError(
            LLMErrorType.CONTENT_FILTER,
            'Content filtered by OpenAI',
            400,
            false
          );
        }
        return new LLMError(
          LLMErrorType.INVALID_REQUEST,
          error.message || 'Invalid request to OpenAI',
          400,
          false
        );

      case 404:
        return new LLMError(
          LLMErrorType.MODEL_NOT_FOUND,
          'Model not found',
          404,
          false
        );

      case 500:
      case 502:
      case 503:
      case 504:
        return new LLMError(
          LLMErrorType.SERVICE_UNAVAILABLE,
          'OpenAI service temporarily unavailable',
          statusCode,
          true
        );

      default:
        if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
          return new LLMError(
            LLMErrorType.NETWORK_ERROR,
            'Network error connecting to OpenAI',
            undefined,
            true
          );
        }

        return new LLMError(
          LLMErrorType.UNKNOWN_ERROR,
          error.message || 'Unknown OpenAI error',
          statusCode,
          false
        );
    }
  }

  /**
   * Helper methods
   */
  private mapFinishReason(reason: string): CompletionResponse['finishReason'] {
    const mapping: Record<string, CompletionResponse['finishReason']> = {
      stop: 'stop',
      length: 'length',
      function_call: 'function_call',
      content_filter: 'content_filter',
    };
    return mapping[reason] || 'stop';
  }

  private getContextWindow(model: string): number {
    const windows: Record<string, number> = {
      'gpt-4': 8192,
      'gpt-4-32k': 32768,
      'gpt-4-turbo': 128000,
      'gpt-3.5-turbo': 4096,
      'gpt-3.5-turbo-16k': 16384,
    };

    for (const [key, value] of Object.entries(windows)) {
      if (model.includes(key)) {
        return value;
      }
    }

    return 4096;
  }

  private getPricing(model: string): { prompt: number; completion: number } {
    // Pricing per 1K tokens in USD
    const pricing: Record<string, { prompt: number; completion: number }> = {
      'gpt-4': { prompt: 0.03, completion: 0.06 },
      'gpt-4-32k': { prompt: 0.06, completion: 0.12 },
      'gpt-4-turbo': { prompt: 0.01, completion: 0.03 },
      'gpt-3.5-turbo': { prompt: 0.0015, completion: 0.002 },
    };

    for (const [key, value] of Object.entries(pricing)) {
      if (model.includes(key)) {
        return value;
      }
    }

    return { prompt: 0.002, completion: 0.002 };
  }

  private calculateCost(
    model: string,
    promptTokens: number,
    completionTokens: number
  ): number {
    const pricing = this.getPricing(model);
    return (
      (promptTokens / 1000) * pricing.prompt +
      (completionTokens / 1000) * pricing.completion
    );
  }

  private estimateTokens(text: string): number {
    // Rough estimation: ~4 characters per token
    return Math.ceil(text.length / 4);
  }
}
```

---

## 4. Best Practices

### 4.1 Error Handling

**DO**:
```typescript
// Categorize errors properly
try {
  await client.analyzeAnomaly(event);
} catch (error) {
  if (error instanceof LLMError) {
    if (error.retryable) {
      // Retry logic is handled automatically
      logger.warn('Retryable error occurred', { errorType: error.type });
    } else {
      // Handle non-retryable errors
      logger.error('Non-retryable error', { errorType: error.type });
      await sendAlert(error);
    }
  } else {
    // Unknown error
    logger.error('Unknown error', { error });
  }
}
```

**DON'T**:
```typescript
// Don't swallow errors
try {
  await client.analyzeAnomaly(event);
} catch (error) {
  console.log('Error occurred'); // No details!
}

// Don't retry non-retryable errors
try {
  await client.analyzeAnomaly(event);
} catch (error) {
  // This bypasses proper error categorization
  await retryOperation();
}
```

### 4.2 Configuration Management

**DO**:
```typescript
// Use environment-specific configuration
const config = ConfigLoader.load(process.env.NODE_ENV || 'development');

// Validate configuration on startup
function validateConfig(config: LLMClientConfig): void {
  if (!config.provider.apiKey) {
    throw new Error('API key is required');
  }

  if (config.resilience.retry.maxAttempts < 1) {
    throw new Error('Max retry attempts must be at least 1');
  }
}
```

**DON'T**:
```typescript
// Don't hardcode API keys
const config = {
  provider: {
    apiKey: 'sk-1234567890', // Never do this!
  },
};

// Don't skip validation
const client = new SentinelLLMClient(untrustedConfig);
```

### 4.3 Logging

**DO**:
```typescript
// Use structured logging
logger.info('Anomaly analysis started', {
  eventId: event.eventId,
  source: event.source,
  timestamp: event.timestamp,
});

// Redact sensitive information
logger.info('Request completed', {
  requestId: request.id,
  model: request.model,
  // Don't log full content - may contain PII
  contentLength: request.messages[0].content.length,
});
```

**DON'T**:
```typescript
// Don't use plain console.log
console.log('Anomaly analysis started'); // No context!

// Don't log sensitive data
logger.info('Request', {
  apiKey: config.apiKey, // Never log API keys!
  userEmail: request.metadata.email, // PII!
});
```

### 4.4 Testing

**DO**:
```typescript
// Use dependency injection for testability
class SentinelLLMClient {
  constructor(
    config: SentinelLLMConfig,
    provider: ILLMProvider, // Injected - easy to mock
    logger: ILogger,
    metrics: IMetrics
  ) {
    // ...
  }
}

// Test with mocks
it('should handle rate limit errors', async () => {
  const mockProvider = new MockLLMProvider();
  mockProvider.setError(
    'test-request',
    new LLMError(LLMErrorType.RATE_LIMIT, 'Rate limit', 429, true)
  );

  const client = new SentinelLLMClient(config, mockProvider, logger, metrics);
  // Test retry behavior
});
```

**DON'T**:
```typescript
// Don't create hard dependencies
class SentinelLLMClient {
  constructor(config: SentinelLLMConfig) {
    this.provider = new OpenAIProvider(config); // Hard to test!
  }
}

// Don't test against real APIs in unit tests
it('should analyze anomaly', async () => {
  const client = new SentinelLLMClient(prodConfig); // Uses real API!
  await client.analyzeAnomaly(event); // Slow, expensive, unreliable
});
```

---

## 5. Testing Guidelines

### 5.1 Unit Testing Strategy

**Coverage Requirements**:
- Minimum 80% code coverage
- 100% coverage for error handling paths
- 100% coverage for validation logic

**Test Organization**:
```
tests/
├── unit/
│   ├── clients/
│   │   ├── sentinel.test.ts
│   │   ├── shield.test.ts
│   │   ├── edge-agent.test.ts
│   │   └── governance.test.ts
│   ├── providers/
│   │   ├── openai.test.ts
│   │   └── anthropic.test.ts
│   ├── resilience/
│   │   ├── retry.test.ts
│   │   ├── circuit-breaker.test.ts
│   │   └── rate-limiter.test.ts
│   └── observability/
│       ├── logger.test.ts
│       └── metrics.test.ts
├── integration/
│   ├── end-to-end.test.ts
│   └── provider-integration.test.ts
└── load/
    └── performance.test.ts
```

### 5.2 Integration Testing

**Example**:
```typescript
describe('Sentinel LLM Client Integration', () => {
  let client: SentinelLLMClient;

  beforeAll(() => {
    // Use test configuration with real provider
    const config = ConfigLoader.load('test');
    client = new SentinelLLMClient(config);
  });

  it('should analyze real anomaly event', async () => {
    const event: AnomalyEvent = {
      eventId: 'integration-test-1',
      timestamp: new Date().toISOString(),
      source: 'integration-test',
      metrics: {
        cpu_usage: 95,
        memory_usage: 85,
        error_rate: 0.05,
      },
      context: {
        service: 'api-gateway',
      },
    };

    const analysis = await client.analyzeAnomaly(event);

    expect(analysis).toBeDefined();
    expect(analysis.isAnomaly).toBeDefined();
    expect(analysis.confidence).toBeGreaterThanOrEqual(0);
    expect(analysis.confidence).toBeLessThanOrEqual(1);
    expect(['P0', 'P1', 'P2', 'P3', 'P4']).toContain(analysis.severity);
  }, 30000);
});
```

### 5.3 Load Testing

**Example**:
```typescript
describe('Load Test', () => {
  it('should handle 100 concurrent requests', async () => {
    const client = new SentinelLLMClient(config);
    const loadTester = new LLMClientLoadTester(client);

    const report = await loadTester.runLoadTest({
      durationSeconds: 60,
      requestsPerSecond: 10,
      concurrentRequests: 100,
    });

    expect(report.successRate).toBeGreaterThan(0.95);
    expect(report.latency.p95).toBeLessThan(5000);
    expect(report.latency.p99).toBeLessThan(10000);
  }, 120000);
});
```

---

## 6. Deployment Checklist

### Pre-Deployment
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Load tests meeting SLA requirements
- [ ] Security scan completed
- [ ] PII redaction verified
- [ ] API keys stored securely
- [ ] Configuration validated for target environment
- [ ] Monitoring dashboards created
- [ ] Alert rules configured
- [ ] Runbook documented

### Deployment
- [ ] Deploy to staging environment
- [ ] Smoke tests in staging
- [ ] Performance tests in staging
- [ ] Enable feature flag for 5% traffic
- [ ] Monitor metrics for 1 hour
- [ ] Increase to 25% traffic
- [ ] Monitor for 2 hours
- [ ] Increase to 50% traffic
- [ ] Monitor for 4 hours
- [ ] Full rollout

### Post-Deployment
- [ ] Verify metrics baseline
- [ ] Confirm error rate < 0.1%
- [ ] Verify p95 latency < 2s
- [ ] Check cost tracking
- [ ] Review logs for warnings
- [ ] Update documentation

---

## 7. Troubleshooting

### Common Issues

#### Issue: High Error Rate

**Symptoms**:
- Error rate > 1%
- Circuit breaker frequently opening

**Diagnosis**:
```typescript
// Check health status
const health = client.getHealthStatus();
console.log('Circuit Breaker State:', health.circuitBreakerState);
console.log('Circuit Breaker Stats:', health.circuitBreakerStats);

// Check logs
logger.info('Error breakdown', {
  errorTypes: metrics.getErrorTypes(),
  errorRate: metrics.getErrorRate(),
});
```

**Resolution**:
1. Check provider API status
2. Verify API keys are valid
3. Review rate limit configuration
4. Increase retry delays if rate limited

#### Issue: Slow Response Times

**Symptoms**:
- p95 latency > 5s
- Timeout errors

**Diagnosis**:
```typescript
// Check rate limiter
const stats = client.rateLimiter.getStats();
console.log('Rate Limiter Stats:', stats);

// Check if waiting for rate limits
logger.info('Rate limit wait times', {
  requestWaits: metrics.getAverageWaitTime('requests'),
  tokenWaits: metrics.getAverageWaitTime('tokens'),
});
```

**Resolution**:
1. Increase rate limits if under quota
2. Reduce concurrent requests
3. Enable caching
4. Use smaller models for non-critical requests

---

## 8. Performance Tuning

### 8.1 Optimization Techniques

**1. Enable Response Caching**:
```typescript
const config: LLMClientConfig = {
  // ...
  features: {
    cachingEnabled: true,
  },
};

// Cache will automatically store and retrieve identical requests
```

**2. Adjust Rate Limits**:
```typescript
const config: LLMClientConfig = {
  // ...
  resilience: {
    rateLimit: {
      enabled: true,
      requestsPerMinute: 100, // Increase if under quota
      tokensPerMinute: 200000,
      burstAllowance: 20, // Allow bursts
    },
  },
};
```

**3. Optimize Prompts**:
```typescript
// Keep prompts concise
// Bad: Very long system prompt with examples
const badPrompt = `
You are an expert system... [5000 tokens of instructions]
`;

// Good: Concise, focused prompt
const goodPrompt = `
Analyze the anomaly and respond with JSON:
{
  "isAnomaly": boolean,
  "severity": "P0"|"P1"|"P2"|"P3"|"P4",
  "recommendations": string[]
}
`;
```

**4. Use Appropriate Models**:
```typescript
// Use smaller models for simple tasks
const severityConfig = {
  ...config,
  provider: {
    ...config.provider,
    defaultModel: 'gpt-3.5-turbo', // Faster, cheaper
  },
};

// Use larger models for complex analysis
const analysisConfig = {
  ...config,
  provider: {
    ...config.provider,
    defaultModel: 'gpt-4', // More accurate
  },
};
```

### 8.2 Monitoring & Alerting

**Key Metrics to Monitor**:
```typescript
// Request metrics
- llm_client.requests.total
- llm_client.requests.duration_ms (p50, p95, p99)
- llm_client.errors.total (by error_type)
- llm_client.errors.rate

// Token usage
- llm_client.tokens.prompt
- llm_client.tokens.completion
- llm_client.tokens.total
- llm_client.cost.estimated

// Resilience metrics
- llm_client.retry.attempts
- llm_client.circuit_breaker.state
- llm_client.rate_limit.wait_ms
```

**Alert Rules**:
```yaml
alerts:
  - name: HighErrorRate
    condition: error_rate > 0.01
    severity: warning
    duration: 5m

  - name: CircuitBreakerOpen
    condition: circuit_breaker_state == 2
    severity: critical
    duration: 1m

  - name: HighLatency
    condition: p95_latency > 5000
    severity: warning
    duration: 10m

  - name: CostSpike
    condition: hourly_cost > 100
    severity: warning
    duration: 1h
```

---

**End of Implementation Guide**

This guide provides comprehensive implementation details, code examples, and best practices for building production-ready LLM clients. Follow the phased approach and reference the code examples to ensure a successful implementation.
