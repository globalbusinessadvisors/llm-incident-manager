# Enterprise LLM Client Architecture Specification

**Version**: 1.0.0
**Status**: Architecture Design
**Author**: SystemArchitect
**Date**: 2025-11-12

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Requirements](#2-system-requirements)
3. [Architecture Overview](#3-architecture-overview)
4. [Class Hierarchy & Design](#4-class-hierarchy--design)
5. [Interface Definitions](#5-interface-definitions)
6. [Configuration Management](#6-configuration-management)
7. [Error Handling Strategy](#7-error-handling-strategy)
8. [Resilience Patterns](#8-resilience-patterns)
9. [Observability & Metrics](#9-observability--metrics)
10. [Testing Strategy](#10-testing-strategy)
11. [Example Usage Patterns](#11-example-usage-patterns)
12. [Security Considerations](#12-security-considerations)
13. [Performance Guidelines](#13-performance-guidelines)
14. [Migration & Deployment](#14-migration--deployment)

---

## 1. Executive Summary

This document specifies the production-grade LLM client architecture for the LLM-Incident-Manager system. The architecture supports four specialized LLM clients:

- **Sentinel LLM Client**: Anomaly detection and monitoring analysis
- **Shield LLM Client**: Security threat analysis and risk assessment
- **Edge-Agent LLM Client**: Distributed edge processing and local inference
- **Governance LLM Client**: Compliance validation and policy enforcement

### Design Goals

1. **Provider Agnostic**: Support multiple LLM providers (OpenAI, Anthropic, Azure OpenAI, etc.)
2. **Enterprise-Grade Resilience**: Circuit breakers, exponential backoff, rate limiting
3. **Type Safety**: Fully typed TypeScript interfaces with runtime validation
4. **Observability**: Comprehensive logging, metrics, and tracing
5. **Testability**: Dependency injection, comprehensive mocking support
6. **Maintainability**: Clear separation of concerns, extensible design

---

## 2. System Requirements

### 2.1 Functional Requirements

| Requirement | Description | Priority |
|-------------|-------------|----------|
| FR-1 | Support OpenAI, Anthropic, Azure OpenAI, Google Vertex AI providers | P0 |
| FR-2 | Automatic retry with exponential backoff for transient failures | P0 |
| FR-3 | Circuit breaker pattern to prevent cascade failures | P0 |
| FR-4 | Request/response logging with PII redaction | P0 |
| FR-5 | Token usage tracking and cost estimation | P1 |
| FR-6 | Rate limiting per provider and per client instance | P0 |
| FR-7 | Timeout handling with configurable limits | P0 |
| FR-8 | Streaming response support for long-running requests | P1 |
| FR-9 | Response caching for identical requests | P2 |
| FR-10 | Request prioritization and queuing | P2 |

### 2.2 Non-Functional Requirements

| Requirement | Description | Target |
|-------------|-------------|--------|
| NFR-1 | Request latency (p95) | < 2s |
| NFR-2 | Request latency (p99) | < 5s |
| NFR-3 | Availability | 99.9% |
| NFR-4 | Error rate | < 0.1% |
| NFR-5 | Memory footprint per client | < 50MB |
| NFR-6 | Concurrent requests per client | > 100 |

### 2.3 Provider Compatibility Matrix

| Feature | OpenAI | Anthropic | Azure OpenAI | Vertex AI |
|---------|--------|-----------|--------------|-----------|
| Chat Completion | ✅ | ✅ | ✅ | ✅ |
| Streaming | ✅ | ✅ | ✅ | ✅ |
| Function Calling | ✅ | ✅ | ✅ | ✅ |
| Vision | ✅ | ✅ | ✅ | ✅ |
| JSON Mode | ✅ | ✅ | ✅ | ⚠️ |

---

## 3. Architecture Overview

### 3.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    LLM Client Architecture                              │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │   Sentinel   │  │    Shield    │  │  Edge-Agent  │  │ Governance  │ │
│  │ LLM Client   │  │  LLM Client  │  │  LLM Client  │  │ LLM Client  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │        │
│         └─────────────────┼─────────────────┼─────────────────┘        │
│                           │                 │                          │
│                           ▼                 ▼                          │
│              ┌────────────────────────────────────────┐                │
│              │      BaseLLMClient (Abstract)          │                │
│              │  ┌──────────────────────────────────┐  │                │
│              │  │  • Request/Response Management   │  │                │
│              │  │  • Common Validation Logic       │  │                │
│              │  │  • Telemetry & Logging           │  │                │
│              │  │  • Configuration Management      │  │                │
│              │  └──────────────────────────────────┘  │                │
│              └────────────┬───────────────────────────┘                │
│                           │                                            │
│         ┌─────────────────┼─────────────────┐                          │
│         ▼                 ▼                 ▼                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
│  │ Resilience  │  │ Observability│  │  Provider   │                    │
│  │  Middleware │  │  Middleware  │  │  Middleware │                    │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤                    │
│  │• Retry      │  │• Logging    │  │• OpenAI     │                    │
│  │• Circuit    │  │• Metrics    │  │• Anthropic  │                    │
│  │  Breaker    │  │• Tracing    │  │• Azure      │                    │
│  │• Rate Limit │  │• Auditing   │  │• Vertex AI  │                    │
│  │• Timeout    │  │             │  │             │                    │
│  └─────────────┘  └─────────────┘  └─────────────┘                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Request Flow Diagram

```
┌─────────────┐
│   Client    │
│ Application │
└──────┬──────┘
       │
       │ 1. Create Request
       ▼
┌──────────────────┐
│ Specialized      │
│ LLM Client       │
│ (Sentinel/Shield)│
└──────┬───────────┘
       │
       │ 2. Validate & Format
       ▼
┌──────────────────┐
│  BaseLLMClient   │
│  - Pre-process   │
│  - Apply middleware
└──────┬───────────┘
       │
       │ 3. Apply Resilience
       ▼
┌──────────────────┐
│ Resilience Layer │
│  - Rate Limiter  │────► Token Bucket
│  - Circuit Breaker│───► State Check
│  - Retry Logic   │────► Backoff Calculator
└──────┬───────────┘
       │
       │ 4. Execute Request
       ▼
┌──────────────────┐
│ Provider Adapter │
│  - OpenAI        │
│  - Anthropic     │
│  - Azure/Vertex  │
└──────┬───────────┘
       │
       │ 5. LLM API Call
       ▼
┌──────────────────┐
│   LLM Provider   │
│   (External)     │
└──────┬───────────┘
       │
       │ 6. Response
       ▼
┌──────────────────┐
│ Observability    │
│  - Log Request   │
│  - Record Metrics│
│  - Emit Trace    │
└──────┬───────────┘
       │
       │ 7. Post-process
       ▼
┌──────────────────┐
│  Return to Client│
│  - Typed Response│
│  - Error Handling│
└──────────────────┘
```

---

## 4. Class Hierarchy & Design

### 4.1 Core Class Structure

```typescript
/**
 * Abstract base class for all LLM clients
 * Provides common functionality and enforces interface contracts
 */
abstract class BaseLLMClient {
  protected config: LLMClientConfig;
  protected provider: ILLMProvider;
  protected resilienceManager: ResilienceManager;
  protected observability: ObservabilityManager;
  protected requestValidator: RequestValidator;

  constructor(config: LLMClientConfig);

  // Abstract methods - must be implemented by subclasses
  abstract validateRequest(request: LLMRequest): ValidationResult;
  abstract formatPrompt(context: any): PromptTemplate;
  abstract parseResponse(response: LLMResponse): any;

  // Common methods - implemented in base class
  protected async executeRequest(request: LLMRequest): Promise<LLMResponse>;
  protected async handleRetry(error: LLMError): Promise<boolean>;
  protected logRequest(request: LLMRequest): void;
  protected logResponse(response: LLMResponse): void;
  protected recordMetrics(metrics: RequestMetrics): void;
}

/**
 * Sentinel LLM Client - Anomaly Detection
 * Specializes in analyzing metrics and detecting anomalies
 */
class SentinelLLMClient extends BaseLLMClient {
  constructor(config: SentinelLLMConfig);

  // Specialized methods for anomaly detection
  async analyzeAnomaly(event: AnomalyEvent): Promise<AnomalyAnalysis>;
  async classifySeverity(metrics: MetricData): Promise<SeverityClassification>;
  async generateInsights(incidents: Incident[]): Promise<Insight[]>;
  async predictImpact(anomaly: Anomaly): Promise<ImpactPrediction>;

  // Override base methods with Sentinel-specific logic
  validateRequest(request: LLMRequest): ValidationResult;
  formatPrompt(context: AnomalyContext): PromptTemplate;
  parseResponse(response: LLMResponse): AnomalyAnalysis;
}

/**
 * Shield LLM Client - Security Analysis
 * Specializes in threat detection and security assessment
 */
class ShieldLLMClient extends BaseLLMClient {
  constructor(config: ShieldLLMConfig);

  // Specialized methods for security analysis
  async analyzeThreat(event: SecurityEvent): Promise<ThreatAnalysis>;
  async assessRisk(vulnerability: Vulnerability): Promise<RiskAssessment>;
  async detectMaliciousPatterns(data: string): Promise<MaliciousPattern[]>;
  async generateMitigationSteps(threat: Threat): Promise<MitigationPlan>;

  // Override base methods with Shield-specific logic
  validateRequest(request: LLMRequest): ValidationResult;
  formatPrompt(context: SecurityContext): PromptTemplate;
  parseResponse(response: LLMResponse): ThreatAnalysis;
}

/**
 * Edge-Agent LLM Client - Distributed Edge Processing
 * Optimized for low-latency, resource-constrained environments
 */
class EdgeAgentLLMClient extends BaseLLMClient {
  private localCache: ResponseCache;
  private offlineQueue: OfflineRequestQueue;

  constructor(config: EdgeAgentLLMConfig);

  // Specialized methods for edge processing
  async processLocalInference(request: InferenceRequest): Promise<InferenceResult>;
  async syncWithCentralHub(data: EdgeData): Promise<SyncResult>;
  async handleOfflineRequest(request: LLMRequest): Promise<QueuedRequest>;
  async prioritizeRequest(requests: LLMRequest[]): Promise<LLMRequest[]>;

  // Override base methods with Edge-specific logic
  validateRequest(request: LLMRequest): ValidationResult;
  formatPrompt(context: EdgeContext): PromptTemplate;
  parseResponse(response: LLMResponse): EdgeProcessingResult;
}

/**
 * Governance LLM Client - Compliance & Policy
 * Specializes in policy validation and compliance checking
 */
class GovernanceLLMClient extends BaseLLMClient {
  private policyEngine: PolicyEngine;
  private complianceChecker: ComplianceChecker;

  constructor(config: GovernanceLLMConfig);

  // Specialized methods for governance
  async validateCompliance(request: ComplianceRequest): Promise<ComplianceResult>;
  async checkPolicy(action: Action, policy: Policy): Promise<PolicyViolation[]>;
  async auditRequest(request: AuditRequest): Promise<AuditReport>;
  async generateComplianceReport(incidents: Incident[]): Promise<ComplianceReport>;

  // Override base methods with Governance-specific logic
  validateRequest(request: LLMRequest): ValidationResult;
  formatPrompt(context: GovernanceContext): PromptTemplate;
  parseResponse(response: LLMResponse): ComplianceResult;
}
```

### 4.2 Provider Adapter Pattern

```typescript
/**
 * Provider interface - all LLM providers must implement this
 */
interface ILLMProvider {
  readonly name: string;
  readonly version: string;
  readonly capabilities: ProviderCapabilities;

  // Core methods
  complete(request: CompletionRequest): Promise<CompletionResponse>;
  stream(request: CompletionRequest): AsyncIterableIterator<CompletionChunk>;
  embeddings(request: EmbeddingRequest): Promise<EmbeddingResponse>;

  // Utility methods
  validateApiKey(): Promise<boolean>;
  getModels(): Promise<ModelInfo[]>;
  estimateCost(request: CompletionRequest): CostEstimate;
}

/**
 * OpenAI Provider Implementation
 */
class OpenAIProvider implements ILLMProvider {
  private client: OpenAI;
  private rateLimiter: RateLimiter;

  constructor(config: OpenAIConfig);

  async complete(request: CompletionRequest): Promise<CompletionResponse> {
    await this.rateLimiter.acquire();

    const openAIRequest = this.transformRequest(request);
    const response = await this.client.chat.completions.create(openAIRequest);

    return this.transformResponse(response);
  }

  async *stream(request: CompletionRequest): AsyncIterableIterator<CompletionChunk> {
    await this.rateLimiter.acquire();

    const openAIRequest = { ...this.transformRequest(request), stream: true };
    const stream = await this.client.chat.completions.create(openAIRequest);

    for await (const chunk of stream) {
      yield this.transformChunk(chunk);
    }
  }

  private transformRequest(request: CompletionRequest): any {
    // Transform generic request to OpenAI format
  }

  private transformResponse(response: any): CompletionResponse {
    // Transform OpenAI response to generic format
  }
}

/**
 * Anthropic Provider Implementation
 */
class AnthropicProvider implements ILLMProvider {
  private client: Anthropic;
  private rateLimiter: RateLimiter;

  constructor(config: AnthropicConfig);

  async complete(request: CompletionRequest): Promise<CompletionResponse> {
    await this.rateLimiter.acquire();

    const anthropicRequest = this.transformRequest(request);
    const response = await this.client.messages.create(anthropicRequest);

    return this.transformResponse(response);
  }

  async *stream(request: CompletionRequest): AsyncIterableIterator<CompletionChunk> {
    await this.rateLimiter.acquire();

    const anthropicRequest = { ...this.transformRequest(request), stream: true };
    const stream = await this.client.messages.create(anthropicRequest);

    for await (const chunk of stream) {
      yield this.transformChunk(chunk);
    }
  }

  private transformRequest(request: CompletionRequest): any {
    // Transform generic request to Anthropic format
  }

  private transformResponse(response: any): CompletionResponse {
    // Transform Anthropic response to generic format
  }
}

/**
 * Provider Factory - creates appropriate provider based on config
 */
class LLMProviderFactory {
  static create(config: ProviderConfig): ILLMProvider {
    switch (config.provider) {
      case 'openai':
        return new OpenAIProvider(config as OpenAIConfig);
      case 'anthropic':
        return new AnthropicProvider(config as AnthropicConfig);
      case 'azure':
        return new AzureOpenAIProvider(config as AzureConfig);
      case 'vertex':
        return new VertexAIProvider(config as VertexConfig);
      default:
        throw new Error(`Unsupported provider: ${config.provider}`);
    }
  }
}
```

### 4.3 Middleware Architecture

```typescript
/**
 * Middleware interface for request/response processing
 */
interface IMiddleware {
  readonly name: string;
  readonly priority: number;

  onRequest(request: LLMRequest, context: RequestContext): Promise<LLMRequest>;
  onResponse(response: LLMResponse, context: RequestContext): Promise<LLMResponse>;
  onError(error: Error, context: RequestContext): Promise<void>;
}

/**
 * Middleware chain executor
 */
class MiddlewareChain {
  private middlewares: IMiddleware[] = [];

  use(middleware: IMiddleware): void {
    this.middlewares.push(middleware);
    this.middlewares.sort((a, b) => a.priority - b.priority);
  }

  async executeRequest(
    request: LLMRequest,
    context: RequestContext
  ): Promise<LLMRequest> {
    let processedRequest = request;

    for (const middleware of this.middlewares) {
      processedRequest = await middleware.onRequest(processedRequest, context);
    }

    return processedRequest;
  }

  async executeResponse(
    response: LLMResponse,
    context: RequestContext
  ): Promise<LLMResponse> {
    let processedResponse = response;

    // Execute in reverse order for response
    for (let i = this.middlewares.length - 1; i >= 0; i--) {
      processedResponse = await this.middlewares[i].onResponse(
        processedResponse,
        context
      );
    }

    return processedResponse;
  }

  async handleError(error: Error, context: RequestContext): Promise<void> {
    for (const middleware of this.middlewares) {
      await middleware.onError(error, context);
    }
  }
}
```

---

## 5. Interface Definitions

### 5.1 Core Type Definitions

```typescript
/**
 * Base LLM request structure
 */
interface LLMRequest {
  id: string;
  timestamp: ISO8601Timestamp;
  model: string;
  messages: Message[];
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
  stopSequences?: string[];
  metadata?: Record<string, any>;
}

/**
 * Message structure for chat-based interactions
 */
interface Message {
  role: 'system' | 'user' | 'assistant' | 'function';
  content: string | ContentBlock[];
  name?: string;
  functionCall?: FunctionCall;
}

/**
 * Content block for multimodal inputs
 */
type ContentBlock = TextBlock | ImageBlock | DocumentBlock;

interface TextBlock {
  type: 'text';
  text: string;
}

interface ImageBlock {
  type: 'image';
  source: {
    type: 'url' | 'base64';
    data: string;
  };
}

interface DocumentBlock {
  type: 'document';
  source: {
    type: 'url' | 'base64';
    data: string;
  };
  mimeType: string;
}

/**
 * Function calling support
 */
interface FunctionCall {
  name: string;
  arguments: Record<string, any>;
}

interface FunctionDefinition {
  name: string;
  description: string;
  parameters: JSONSchema;
}

/**
 * LLM response structure
 */
interface LLMResponse {
  id: string;
  requestId: string;
  timestamp: ISO8601Timestamp;
  model: string;
  content: string;
  role: 'assistant';
  functionCall?: FunctionCall;
  finishReason: 'stop' | 'length' | 'function_call' | 'content_filter';
  usage: TokenUsage;
  metadata?: Record<string, any>;
}

/**
 * Token usage tracking
 */
interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCost?: number;
}

/**
 * Streaming response chunk
 */
interface CompletionChunk {
  id: string;
  delta: {
    role?: 'assistant';
    content?: string;
    functionCall?: Partial<FunctionCall>;
  };
  finishReason?: string;
}

/**
 * Error categorization
 */
enum LLMErrorType {
  // Retryable errors
  RATE_LIMIT = 'RATE_LIMIT',
  TIMEOUT = 'TIMEOUT',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  NETWORK_ERROR = 'NETWORK_ERROR',

  // Non-retryable errors
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  INVALID_REQUEST = 'INVALID_REQUEST',
  CONTENT_FILTER = 'CONTENT_FILTER',
  MODEL_NOT_FOUND = 'MODEL_NOT_FOUND',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',

  // Circuit breaker
  CIRCUIT_OPEN = 'CIRCUIT_OPEN',

  // Unknown
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/**
 * LLM error with metadata
 */
class LLMError extends Error {
  constructor(
    public type: LLMErrorType,
    public message: string,
    public statusCode?: number,
    public retryable: boolean = false,
    public metadata?: Record<string, any>
  ) {
    super(message);
    this.name = 'LLMError';
  }

  static fromProviderError(error: any, provider: string): LLMError {
    // Provider-specific error mapping
  }
}
```

### 5.2 Specialized Client Interfaces

```typescript
/**
 * Sentinel-specific types
 */
interface AnomalyEvent {
  eventId: string;
  timestamp: ISO8601Timestamp;
  source: string;
  metrics: MetricData;
  context: Record<string, any>;
}

interface AnomalyAnalysis {
  isAnomaly: boolean;
  confidence: number;
  severity: 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
  rootCause?: string;
  recommendations: string[];
  relatedIncidents?: string[];
}

interface MetricData {
  [key: string]: number | string;
}

interface SeverityClassification {
  severity: 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
  confidence: number;
  reasoning: string;
  factors: string[];
}

/**
 * Shield-specific types
 */
interface SecurityEvent {
  eventId: string;
  timestamp: ISO8601Timestamp;
  eventType: string;
  payload: string;
  context: SecurityContext;
}

interface SecurityContext {
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  apiKey?: string;
  requestPath?: string;
}

interface ThreatAnalysis {
  isThreat: boolean;
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  confidence: number;
  threatType?: string[];
  indicators: string[];
  mitigationSteps: string[];
}

interface RiskAssessment {
  riskScore: number; // 0-100
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  vulnerabilities: Vulnerability[];
  recommendations: string[];
}

/**
 * Edge-Agent specific types
 */
interface EdgeContext {
  nodeId: string;
  region: string;
  available Resources: ResourceInfo;
  networkQuality: 'high' | 'medium' | 'low';
}

interface EdgeProcessingResult {
  processedLocally: boolean;
  fallbackToCentral: boolean;
  result: any;
  latency: number;
  resourceUsage: ResourceUsage;
}

interface ResourceUsage {
  cpuPercent: number;
  memoryMB: number;
  networkKbps: number;
}

/**
 * Governance-specific types
 */
interface ComplianceRequest {
  requestId: string;
  action: string;
  context: GovernanceContext;
  policies: string[];
}

interface GovernanceContext {
  userId: string;
  tenantId: string;
  environment: 'production' | 'staging' | 'development';
  dataClassification?: string;
}

interface ComplianceResult {
  compliant: boolean;
  violations: PolicyViolation[];
  warnings: string[];
  auditTrail: AuditEntry[];
}

interface PolicyViolation {
  policyId: string;
  policyName: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
}
```

---

## 6. Configuration Management

### 6.1 Configuration Schema

```typescript
/**
 * Base LLM client configuration
 */
interface LLMClientConfig {
  // Client identification
  clientId: string;
  clientName: string;
  version: string;

  // Provider configuration
  provider: ProviderConfig;

  // Resilience settings
  resilience: ResilienceConfig;

  // Observability settings
  observability: ObservabilityConfig;

  // Feature flags
  features: FeatureConfig;

  // Environment
  environment: 'production' | 'staging' | 'development' | 'test';
}

/**
 * Provider configuration
 */
interface ProviderConfig {
  provider: 'openai' | 'anthropic' | 'azure' | 'vertex';
  apiKey: string;
  baseUrl?: string;
  organization?: string;
  apiVersion?: string;

  // Model configuration
  defaultModel: string;
  availableModels: string[];

  // Request defaults
  defaultTemperature: number;
  defaultMaxTokens: number;
  defaultTopP: number;
}

/**
 * OpenAI-specific configuration
 */
interface OpenAIConfig extends ProviderConfig {
  provider: 'openai';
  organization?: string;
  azureDeployment?: string; // For Azure OpenAI
}

/**
 * Anthropic-specific configuration
 */
interface AnthropicConfig extends ProviderConfig {
  provider: 'anthropic';
  anthropicVersion: string;
}

/**
 * Resilience configuration
 */
interface ResilienceConfig {
  // Retry configuration
  retry: RetryConfig;

  // Circuit breaker configuration
  circuitBreaker: CircuitBreakerConfig;

  // Rate limiting
  rateLimit: RateLimitConfig;

  // Timeout configuration
  timeout: TimeoutConfig;
}

/**
 * Retry configuration with exponential backoff
 */
interface RetryConfig {
  enabled: boolean;
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  jitterMs: number;
  retryableErrors: LLMErrorType[];
}

/**
 * Circuit breaker configuration
 */
interface CircuitBreakerConfig {
  enabled: boolean;
  failureThreshold: number;
  successThreshold: number;
  timeout: number;
  halfOpenMaxAttempts: number;
  volumeThreshold: number; // Minimum number of requests before opening
}

/**
 * Rate limiting configuration
 */
interface RateLimitConfig {
  enabled: boolean;
  requestsPerMinute: number;
  requestsPerHour: number;
  tokensPerMinute: number;
  tokensPerDay: number;
  burstAllowance: number;
}

/**
 * Timeout configuration
 */
interface TimeoutConfig {
  requestTimeoutMs: number;
  connectionTimeoutMs: number;
  streamTimeoutMs: number;
}

/**
 * Observability configuration
 */
interface ObservabilityConfig {
  // Logging
  logging: LoggingConfig;

  // Metrics
  metrics: MetricsConfig;

  // Tracing
  tracing: TracingConfig;

  // Auditing
  auditing: AuditConfig;
}

/**
 * Logging configuration
 */
interface LoggingConfig {
  enabled: boolean;
  level: 'debug' | 'info' | 'warn' | 'error';
  logRequests: boolean;
  logResponses: boolean;
  redactPII: boolean;
  redactApiKeys: boolean;
  maxBodyLength: number;
}

/**
 * Metrics configuration
 */
interface MetricsConfig {
  enabled: boolean;
  prefix: string;
  labels: Record<string, string>;
  exportInterval: number;
  exportEndpoint?: string;
}

/**
 * Tracing configuration
 */
interface TracingConfig {
  enabled: boolean;
  serviceName: string;
  samplingRate: number;
  exportEndpoint?: string;
}

/**
 * Audit configuration
 */
interface AuditConfig {
  enabled: boolean;
  logAllRequests: boolean;
  logFailedRequests: boolean;
  retentionDays: number;
  storageBackend: 'file' | 'database' | 's3';
}

/**
 * Feature flags
 */
interface FeatureConfig {
  streamingEnabled: boolean;
  functionCallingEnabled: boolean;
  cachingEnabled: boolean;
  embeddingsEnabled: boolean;
  visionEnabled: boolean;
}

/**
 * Environment-based configuration loader
 */
class ConfigLoader {
  static load(environment: string): LLMClientConfig {
    const configPath = `./config/${environment}.json`;
    const envOverrides = this.loadEnvOverrides();
    const baseConfig = this.loadFile(configPath);

    return this.merge(baseConfig, envOverrides);
  }

  private static loadEnvOverrides(): Partial<LLMClientConfig> {
    return {
      provider: {
        apiKey: process.env.LLM_API_KEY || '',
        baseUrl: process.env.LLM_BASE_URL,
        defaultModel: process.env.LLM_DEFAULT_MODEL || 'gpt-4',
      },
      observability: {
        logging: {
          level: (process.env.LOG_LEVEL as any) || 'info',
        },
      },
    };
  }

  private static loadFile(path: string): LLMClientConfig {
    // Load configuration from file
  }

  private static merge(
    base: LLMClientConfig,
    overrides: Partial<LLMClientConfig>
  ): LLMClientConfig {
    // Deep merge configuration objects
  }
}
```

### 6.2 Example Configuration Files

**config/production.json**
```json
{
  "clientId": "sentinel-llm-prod",
  "clientName": "Sentinel LLM Client",
  "version": "1.0.0",
  "provider": {
    "provider": "anthropic",
    "apiKey": "${ANTHROPIC_API_KEY}",
    "defaultModel": "claude-3-5-sonnet-20241022",
    "availableModels": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229"],
    "defaultTemperature": 0.7,
    "defaultMaxTokens": 4096,
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
      "retryableErrors": ["RATE_LIMIT", "TIMEOUT", "SERVICE_UNAVAILABLE", "NETWORK_ERROR"]
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
      "level": "info",
      "logRequests": true,
      "logResponses": true,
      "redactPII": true,
      "redactApiKeys": true,
      "maxBodyLength": 10000
    },
    "metrics": {
      "enabled": true,
      "prefix": "llm_client.sentinel",
      "labels": {
        "environment": "production",
        "client": "sentinel"
      },
      "exportInterval": 60000,
      "exportEndpoint": "http://metrics-collector:9090/metrics"
    },
    "tracing": {
      "enabled": true,
      "serviceName": "sentinel-llm-client",
      "samplingRate": 0.1,
      "exportEndpoint": "http://jaeger:14268/api/traces"
    },
    "auditing": {
      "enabled": true,
      "logAllRequests": true,
      "logFailedRequests": true,
      "retentionDays": 90,
      "storageBackend": "database"
    }
  },
  "features": {
    "streamingEnabled": true,
    "functionCallingEnabled": true,
    "cachingEnabled": true,
    "embeddingsEnabled": false,
    "visionEnabled": false
  },
  "environment": "production"
}
```

**config/development.json**
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
      "maxAttempts": 2,
      "baseDelayMs": 500,
      "maxDelayMs": 10000,
      "backoffMultiplier": 2,
      "jitterMs": 50,
      "retryableErrors": ["RATE_LIMIT", "TIMEOUT", "SERVICE_UNAVAILABLE"]
    },
    "circuitBreaker": {
      "enabled": false,
      "failureThreshold": 10,
      "successThreshold": 3,
      "timeout": 30000,
      "halfOpenMaxAttempts": 1,
      "volumeThreshold": 20
    },
    "rateLimit": {
      "enabled": false,
      "requestsPerMinute": 100,
      "requestsPerHour": 5000,
      "tokensPerMinute": 200000,
      "tokensPerDay": 10000000,
      "burstAllowance": 20
    },
    "timeout": {
      "requestTimeoutMs": 60000,
      "connectionTimeoutMs": 10000,
      "streamTimeoutMs": 180000
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
      "enabled": false,
      "prefix": "llm_client.sentinel",
      "labels": {
        "environment": "development",
        "client": "sentinel"
      },
      "exportInterval": 300000,
      "exportEndpoint": ""
    },
    "tracing": {
      "enabled": false,
      "serviceName": "sentinel-llm-client",
      "samplingRate": 1.0,
      "exportEndpoint": ""
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

## 7. Error Handling Strategy

### 7.1 Error Classification & Recovery

```typescript
/**
 * Error handler with categorization and recovery logic
 */
class LLMErrorHandler {
  private logger: ILogger;
  private metrics: IMetrics;

  constructor(logger: ILogger, metrics: IMetrics) {
    this.logger = logger;
    this.metrics = metrics;
  }

  /**
   * Categorize error and determine if retryable
   */
  categorizeError(error: any, provider: string): LLMError {
    // Provider-specific error mapping
    if (provider === 'openai') {
      return this.categorizeOpenAIError(error);
    } else if (provider === 'anthropic') {
      return this.categorizeAnthropicError(error);
    }

    return new LLMError(
      LLMErrorType.UNKNOWN_ERROR,
      error.message || 'Unknown error',
      undefined,
      false
    );
  }

  /**
   * OpenAI error categorization
   */
  private categorizeOpenAIError(error: any): LLMError {
    const statusCode = error.status || error.statusCode;

    switch (statusCode) {
      case 429:
        return new LLMError(
          LLMErrorType.RATE_LIMIT,
          'Rate limit exceeded',
          429,
          true,
          { retryAfter: error.headers?.['retry-after'] }
        );

      case 401:
      case 403:
        return new LLMError(
          LLMErrorType.AUTHENTICATION_ERROR,
          'Authentication failed',
          statusCode,
          false
        );

      case 400:
        if (error.message?.includes('content_filter')) {
          return new LLMError(
            LLMErrorType.CONTENT_FILTER,
            'Content filtered by provider',
            400,
            false
          );
        }
        return new LLMError(
          LLMErrorType.INVALID_REQUEST,
          error.message || 'Invalid request',
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
          'Service temporarily unavailable',
          statusCode,
          true
        );

      default:
        if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
          return new LLMError(
            LLMErrorType.NETWORK_ERROR,
            'Network error',
            undefined,
            true
          );
        }

        return new LLMError(
          LLMErrorType.UNKNOWN_ERROR,
          error.message || 'Unknown error',
          statusCode,
          false
        );
    }
  }

  /**
   * Anthropic error categorization
   */
  private categorizeAnthropicError(error: any): LLMError {
    const statusCode = error.status_code || error.statusCode;

    switch (statusCode) {
      case 429:
        return new LLMError(
          LLMErrorType.RATE_LIMIT,
          'Rate limit exceeded',
          429,
          true,
          { retryAfter: error.retry_after }
        );

      case 401:
        return new LLMError(
          LLMErrorType.AUTHENTICATION_ERROR,
          'Invalid API key',
          401,
          false
        );

      case 400:
        return new LLMError(
          LLMErrorType.INVALID_REQUEST,
          error.message || 'Invalid request',
          400,
          false
        );

      case 500:
      case 529:
        return new LLMError(
          LLMErrorType.SERVICE_UNAVAILABLE,
          'Service overloaded',
          statusCode,
          true
        );

      default:
        return new LLMError(
          LLMErrorType.UNKNOWN_ERROR,
          error.message || 'Unknown error',
          statusCode,
          false
        );
    }
  }

  /**
   * Handle error with appropriate recovery strategy
   */
  async handleError(
    error: LLMError,
    context: RequestContext
  ): Promise<ErrorRecoveryAction> {
    // Log error
    this.logger.error('LLM request failed', {
      errorType: error.type,
      message: error.message,
      statusCode: error.statusCode,
      requestId: context.requestId,
      retryable: error.retryable,
    });

    // Record metrics
    this.metrics.increment('llm_client.errors', {
      error_type: error.type,
      retryable: error.retryable.toString(),
    });

    // Determine recovery action
    if (error.retryable) {
      return {
        action: 'retry',
        delayMs: this.calculateRetryDelay(error, context),
      };
    } else if (error.type === LLMErrorType.CIRCUIT_OPEN) {
      return {
        action: 'circuit_open',
        message: 'Circuit breaker is open',
      };
    } else {
      return {
        action: 'fail',
        error: error,
      };
    }
  }

  /**
   * Calculate retry delay based on error type
   */
  private calculateRetryDelay(error: LLMError, context: RequestContext): number {
    if (error.metadata?.retryAfter) {
      return parseInt(error.metadata.retryAfter) * 1000;
    }

    // Exponential backoff
    const baseDelay = context.config.resilience.retry.baseDelayMs;
    const attempt = context.retryCount || 0;
    const multiplier = context.config.resilience.retry.backoffMultiplier;
    const jitter = context.config.resilience.retry.jitterMs;

    const exponentialDelay = baseDelay * Math.pow(multiplier, attempt);
    const withJitter = exponentialDelay + Math.random() * jitter;

    return Math.min(
      withJitter,
      context.config.resilience.retry.maxDelayMs
    );
  }
}

/**
 * Error recovery action
 */
interface ErrorRecoveryAction {
  action: 'retry' | 'circuit_open' | 'fail';
  delayMs?: number;
  error?: LLMError;
  message?: string;
}

/**
 * Request context for error handling
 */
interface RequestContext {
  requestId: string;
  retryCount: number;
  startTime: number;
  config: LLMClientConfig;
  metadata: Record<string, any>;
}
```

### 7.2 Error Logging & Alerting

```typescript
/**
 * Error logger with structured logging
 */
class ErrorLogger {
  private logger: ILogger;

  constructor(logger: ILogger) {
    this.logger = logger;
  }

  logError(error: LLMError, context: RequestContext): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: this.getLogLevel(error),
      requestId: context.requestId,
      error: {
        type: error.type,
        message: error.message,
        statusCode: error.statusCode,
        retryable: error.retryable,
        stack: error.stack,
      },
      context: {
        retryCount: context.retryCount,
        durationMs: Date.now() - context.startTime,
        ...context.metadata,
      },
    };

    // Redact sensitive information
    const sanitized = this.redactSensitiveData(logEntry);

    // Log based on severity
    if (this.shouldAlert(error)) {
      this.logger.error('Critical LLM error', sanitized);
      this.sendAlert(error, context);
    } else {
      this.logger.warn('LLM error', sanitized);
    }
  }

  private getLogLevel(error: LLMError): string {
    switch (error.type) {
      case LLMErrorType.AUTHENTICATION_ERROR:
      case LLMErrorType.QUOTA_EXCEEDED:
        return 'error';
      case LLMErrorType.RATE_LIMIT:
      case LLMErrorType.TIMEOUT:
        return 'warn';
      default:
        return 'info';
    }
  }

  private shouldAlert(error: LLMError): boolean {
    return [
      LLMErrorType.AUTHENTICATION_ERROR,
      LLMErrorType.QUOTA_EXCEEDED,
      LLMErrorType.CIRCUIT_OPEN,
    ].includes(error.type);
  }

  private redactSensitiveData(logEntry: any): any {
    // Implement PII and API key redaction
    return logEntry;
  }

  private async sendAlert(error: LLMError, context: RequestContext): Promise<void> {
    // Send alert to incident management system
    // This integrates with the main incident system
  }
}
```

---

## 8. Resilience Patterns

### 8.1 Retry with Exponential Backoff

```typescript
/**
 * Retry manager with exponential backoff
 */
class RetryManager {
  private config: RetryConfig;
  private logger: ILogger;
  private metrics: IMetrics;

  constructor(config: RetryConfig, logger: ILogger, metrics: IMetrics) {
    this.config = config;
    this.logger = logger;
    this.metrics = metrics;
  }

  async executeWithRetry<T>(
    operation: () => Promise<T>,
    context: RequestContext
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 0; attempt <= this.config.maxAttempts; attempt++) {
      try {
        context.retryCount = attempt;

        // Execute operation
        const result = await operation();

        // Record success metrics
        if (attempt > 0) {
          this.metrics.increment('llm_client.retry.success', {
            attempt: attempt.toString(),
          });
        }

        return result;
      } catch (error) {
        lastError = error as Error;

        // Check if we should retry
        if (attempt >= this.config.maxAttempts) {
          this.logger.error('Max retry attempts reached', {
            requestId: context.requestId,
            attempts: attempt + 1,
          });
          break;
        }

        // Check if error is retryable
        const llmError = error as LLMError;
        if (!llmError.retryable) {
          this.logger.debug('Non-retryable error, not retrying', {
            errorType: llmError.type,
          });
          break;
        }

        // Calculate delay
        const delayMs = this.calculateBackoff(attempt, llmError);

        this.logger.info('Retrying request', {
          requestId: context.requestId,
          attempt: attempt + 1,
          maxAttempts: this.config.maxAttempts,
          delayMs,
          errorType: llmError.type,
        });

        // Record retry metrics
        this.metrics.increment('llm_client.retry.attempt', {
          attempt: attempt.toString(),
          error_type: llmError.type,
        });

        // Wait before retry
        await this.delay(delayMs);
      }
    }

    // All retries failed
    this.metrics.increment('llm_client.retry.exhausted');
    throw lastError!;
  }

  private calculateBackoff(attempt: number, error?: LLMError): number {
    // Use retry-after header if available
    if (error?.metadata?.retryAfter) {
      return parseInt(error.metadata.retryAfter) * 1000;
    }

    // Exponential backoff with jitter
    const exponentialDelay =
      this.config.baseDelayMs * Math.pow(this.config.backoffMultiplier, attempt);

    const jitter = Math.random() * this.config.jitterMs;

    const totalDelay = exponentialDelay + jitter;

    return Math.min(totalDelay, this.config.maxDelayMs);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### 8.2 Circuit Breaker Pattern

```typescript
/**
 * Circuit breaker states
 */
enum CircuitState {
  CLOSED = 'CLOSED',     // Normal operation
  OPEN = 'OPEN',         // Failing, rejecting requests
  HALF_OPEN = 'HALF_OPEN', // Testing if service recovered
}

/**
 * Circuit breaker implementation
 */
class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number = 0;
  private requestCount: number = 0;
  private halfOpenAttempts: number = 0;

  private config: CircuitBreakerConfig;
  private logger: ILogger;
  private metrics: IMetrics;

  constructor(
    config: CircuitBreakerConfig,
    logger: ILogger,
    metrics: IMetrics
  ) {
    this.config = config;
    this.logger = logger;
    this.metrics = metrics;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    // Check if circuit is open
    if (this.state === CircuitState.OPEN) {
      if (this.shouldAttemptReset()) {
        this.transitionToHalfOpen();
      } else {
        throw new LLMError(
          LLMErrorType.CIRCUIT_OPEN,
          'Circuit breaker is open',
          undefined,
          false,
          { state: this.state }
        );
      }
    }

    // Check if we're in half-open state
    if (this.state === CircuitState.HALF_OPEN) {
      if (this.halfOpenAttempts >= this.config.halfOpenMaxAttempts) {
        throw new LLMError(
          LLMErrorType.CIRCUIT_OPEN,
          'Circuit breaker is half-open, max attempts reached',
          undefined,
          false
        );
      }
      this.halfOpenAttempts++;
    }

    try {
      // Execute operation
      const result = await operation();

      // Record success
      this.onSuccess();

      return result;
    } catch (error) {
      // Record failure
      this.onFailure();

      throw error;
    }
  }

  private onSuccess(): void {
    this.successCount++;
    this.requestCount++;

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.successCount >= this.config.successThreshold) {
        this.transitionToClosed();
      }
    } else {
      // Reset failure count on success in closed state
      this.failureCount = 0;
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.requestCount++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.transitionToOpen();
    } else if (this.state === CircuitState.CLOSED) {
      if (
        this.requestCount >= this.config.volumeThreshold &&
        this.failureCount >= this.config.failureThreshold
      ) {
        this.transitionToOpen();
      }
    }
  }

  private shouldAttemptReset(): boolean {
    const timeSinceLastFailure = Date.now() - this.lastFailureTime;
    return timeSinceLastFailure >= this.config.timeout;
  }

  private transitionToOpen(): void {
    this.logger.warn('Circuit breaker transitioning to OPEN', {
      failureCount: this.failureCount,
      requestCount: this.requestCount,
    });

    this.state = CircuitState.OPEN;
    this.halfOpenAttempts = 0;

    this.metrics.increment('llm_client.circuit_breaker.open');
    this.emitStateChange();
  }

  private transitionToHalfOpen(): void {
    this.logger.info('Circuit breaker transitioning to HALF_OPEN');

    this.state = CircuitState.HALF_OPEN;
    this.halfOpenAttempts = 0;
    this.successCount = 0;

    this.metrics.increment('llm_client.circuit_breaker.half_open');
    this.emitStateChange();
  }

  private transitionToClosed(): void {
    this.logger.info('Circuit breaker transitioning to CLOSED');

    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.requestCount = 0;
    this.halfOpenAttempts = 0;

    this.metrics.increment('llm_client.circuit_breaker.closed');
    this.emitStateChange();
  }

  private emitStateChange(): void {
    this.metrics.gauge('llm_client.circuit_breaker.state',
      this.state === CircuitState.CLOSED ? 0 :
      this.state === CircuitState.HALF_OPEN ? 1 : 2
    );
  }

  getState(): CircuitState {
    return this.state;
  }

  getStats() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      requestCount: this.requestCount,
      lastFailureTime: this.lastFailureTime,
    };
  }
}
```

### 8.3 Rate Limiting with Token Bucket

```typescript
/**
 * Token bucket rate limiter
 */
class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefill: number;
  private config: RateLimitConfig;
  private logger: ILogger;
  private metrics: IMetrics;

  // Separate buckets for different limits
  private requestBucket: TokenBucket;
  private tokenBucket: TokenBucket;

  constructor(
    config: RateLimitConfig,
    logger: ILogger,
    metrics: IMetrics
  ) {
    this.config = config;
    this.logger = logger;
    this.metrics = metrics;

    // Initialize buckets
    this.requestBucket = new TokenBucket(
      config.requestsPerMinute,
      config.requestsPerMinute / 60, // refill rate per second
      config.burstAllowance
    );

    this.tokenBucket = new TokenBucket(
      config.tokensPerMinute,
      config.tokensPerMinute / 60,
      config.burstAllowance * 1000 // larger burst for tokens
    );
  }

  async acquire(estimatedTokens: number = 1000): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    // Check request limit
    const requestWaitMs = this.requestBucket.tryConsume(1);
    if (requestWaitMs > 0) {
      this.logger.debug('Rate limit: requests per minute exceeded', {
        waitMs: requestWaitMs,
      });

      this.metrics.increment('llm_client.rate_limit.requests.wait');
      await this.delay(requestWaitMs);
    }

    // Check token limit
    const tokenWaitMs = this.tokenBucket.tryConsume(estimatedTokens);
    if (tokenWaitMs > 0) {
      this.logger.debug('Rate limit: tokens per minute exceeded', {
        waitMs: tokenWaitMs,
        estimatedTokens,
      });

      this.metrics.increment('llm_client.rate_limit.tokens.wait');
      await this.delay(tokenWaitMs);
    }
  }

  recordActualUsage(actualTokens: number): void {
    // Adjust token bucket based on actual usage
    const difference = actualTokens - 1000; // Assuming we estimated 1000
    if (difference > 0) {
      this.tokenBucket.tryConsume(difference);
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  getStats() {
    return {
      requestBucket: this.requestBucket.getStats(),
      tokenBucket: this.tokenBucket.getStats(),
    };
  }
}

/**
 * Token bucket implementation
 */
class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private capacity: number,
    private refillRate: number, // tokens per second
    private burstAllowance: number
  ) {
    this.tokens = capacity + burstAllowance;
    this.lastRefill = Date.now();
  }

  tryConsume(tokensNeeded: number): number {
    this.refill();

    if (this.tokens >= tokensNeeded) {
      this.tokens -= tokensNeeded;
      return 0; // No wait needed
    }

    // Calculate wait time
    const tokensShortage = tokensNeeded - this.tokens;
    const waitMs = (tokensShortage / this.refillRate) * 1000;

    return Math.ceil(waitMs);
  }

  private refill(): void {
    const now = Date.now();
    const timePassed = (now - this.lastRefill) / 1000; // seconds
    const tokensToAdd = timePassed * this.refillRate;

    this.tokens = Math.min(
      this.capacity + this.burstAllowance,
      this.tokens + tokensToAdd
    );

    this.lastRefill = now;
  }

  getStats() {
    this.refill();
    return {
      tokens: this.tokens,
      capacity: this.capacity,
      refillRate: this.refillRate,
    };
  }
}
```

### 8.4 Timeout Management

```typescript
/**
 * Timeout manager with cancellation support
 */
class TimeoutManager {
  private config: TimeoutConfig;
  private logger: ILogger;

  constructor(config: TimeoutConfig, logger: ILogger) {
    this.config = config;
    this.logger = logger;
  }

  async executeWithTimeout<T>(
    operation: () => Promise<T>,
    timeoutMs: number,
    context: RequestContext
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new LLMError(
          LLMErrorType.TIMEOUT,
          `Request timed out after ${timeoutMs}ms`,
          undefined,
          true,
          { timeoutMs, requestId: context.requestId }
        ));
      }, timeoutMs);
    });

    try {
      return await Promise.race([operation(), timeoutPromise]);
    } catch (error) {
      if (error instanceof LLMError && error.type === LLMErrorType.TIMEOUT) {
        this.logger.warn('Request timed out', {
          requestId: context.requestId,
          timeoutMs,
        });
      }
      throw error;
    }
  }

  getRequestTimeout(isStreaming: boolean): number {
    return isStreaming
      ? this.config.streamTimeoutMs
      : this.config.requestTimeoutMs;
  }
}
```

---

## 9. Observability & Metrics

### 9.1 Logging Implementation

```typescript
/**
 * Structured logger interface
 */
interface ILogger {
  debug(message: string, context?: Record<string, any>): void;
  info(message: string, context?: Record<string, any>): void;
  warn(message: string, context?: Record<string, any>): void;
  error(message: string, context?: Record<string, any>): void;
}

/**
 * LLM Client logger with PII redaction
 */
class LLMClientLogger implements ILogger {
  private config: LoggingConfig;
  private baseLogger: ILogger;

  constructor(config: LoggingConfig, baseLogger: ILogger) {
    this.config = config;
    this.baseLogger = baseLogger;
  }

  debug(message: string, context?: Record<string, any>): void {
    if (this.shouldLog('debug')) {
      this.baseLogger.debug(message, this.sanitize(context));
    }
  }

  info(message: string, context?: Record<string, any>): void {
    if (this.shouldLog('info')) {
      this.baseLogger.info(message, this.sanitize(context));
    }
  }

  warn(message: string, context?: Record<string, any>): void {
    if (this.shouldLog('warn')) {
      this.baseLogger.warn(message, this.sanitize(context));
    }
  }

  error(message: string, context?: Record<string, any>): void {
    if (this.shouldLog('error')) {
      this.baseLogger.error(message, this.sanitize(context));
    }
  }

  logRequest(request: LLMRequest): void {
    if (!this.config.logRequests) return;

    const sanitized = this.sanitizeRequest(request);

    this.info('LLM request', {
      requestId: request.id,
      model: request.model,
      messageCount: request.messages.length,
      temperature: request.temperature,
      maxTokens: request.maxTokens,
      ...sanitized,
    });
  }

  logResponse(response: LLMResponse, durationMs: number): void {
    if (!this.config.logResponses) return;

    const sanitized = this.sanitizeResponse(response);

    this.info('LLM response', {
      requestId: response.requestId,
      responseId: response.id,
      model: response.model,
      finishReason: response.finishReason,
      promptTokens: response.usage.promptTokens,
      completionTokens: response.usage.completionTokens,
      totalTokens: response.usage.totalTokens,
      estimatedCost: response.usage.estimatedCost,
      durationMs,
      ...sanitized,
    });
  }

  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    const configLevel = levels.indexOf(this.config.level);
    const messageLevel = levels.indexOf(level);

    return messageLevel >= configLevel;
  }

  private sanitize(context?: Record<string, any>): Record<string, any> | undefined {
    if (!context) return undefined;

    const sanitized = { ...context };

    if (this.config.redactApiKeys) {
      sanitized.apiKey = '[REDACTED]';
      sanitized.authorization = '[REDACTED]';
    }

    if (this.config.redactPII) {
      // Implement PII redaction logic
      sanitized.email = this.redactEmail(sanitized.email);
      sanitized.phone = this.redactPhone(sanitized.phone);
    }

    return sanitized;
  }

  private sanitizeRequest(request: LLMRequest): any {
    const sanitized: any = {};

    if (this.config.maxBodyLength > 0) {
      const content = JSON.stringify(request.messages);
      sanitized.messagesPreview = content.substring(0, this.config.maxBodyLength);
      sanitized.messagesTruncated = content.length > this.config.maxBodyLength;
    }

    return sanitized;
  }

  private sanitizeResponse(response: LLMResponse): any {
    const sanitized: any = {};

    if (this.config.maxBodyLength > 0) {
      sanitized.contentPreview = response.content.substring(
        0,
        this.config.maxBodyLength
      );
      sanitized.contentTruncated =
        response.content.length > this.config.maxBodyLength;
    }

    return sanitized;
  }

  private redactEmail(email?: string): string | undefined {
    if (!email) return undefined;
    return email.replace(/(.{2})(.*)(@.*)/, '$1***$3');
  }

  private redactPhone(phone?: string): string | undefined {
    if (!phone) return undefined;
    return phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1-***-$3');
  }
}
```

### 9.2 Metrics Collection

```typescript
/**
 * Metrics interface
 */
interface IMetrics {
  increment(metric: string, labels?: Record<string, string>, value?: number): void;
  gauge(metric: string, value: number, labels?: Record<string, string>): void;
  histogram(metric: string, value: number, labels?: Record<string, string>): void;
  timer(metric: string): () => void;
}

/**
 * LLM Client metrics collector
 */
class LLMClientMetrics {
  private metrics: IMetrics;
  private config: MetricsConfig;

  constructor(metrics: IMetrics, config: MetricsConfig) {
    this.metrics = metrics;
    this.config = config;
  }

  recordRequest(request: LLMRequest): void {
    this.metrics.increment(`${this.config.prefix}.requests.total`, {
      model: request.model,
      ...this.config.labels,
    });
  }

  recordResponse(
    response: LLMResponse,
    durationMs: number,
    success: boolean
  ): void {
    // Request duration
    this.metrics.histogram(
      `${this.config.prefix}.request.duration_ms`,
      durationMs,
      {
        model: response.model,
        success: success.toString(),
        ...this.config.labels,
      }
    );

    // Token usage
    this.metrics.histogram(
      `${this.config.prefix}.tokens.prompt`,
      response.usage.promptTokens,
      { model: response.model, ...this.config.labels }
    );

    this.metrics.histogram(
      `${this.config.prefix}.tokens.completion`,
      response.usage.completionTokens,
      { model: response.model, ...this.config.labels }
    );

    this.metrics.histogram(
      `${this.config.prefix}.tokens.total`,
      response.usage.totalTokens,
      { model: response.model, ...this.config.labels }
    );

    // Cost
    if (response.usage.estimatedCost) {
      this.metrics.histogram(
        `${this.config.prefix}.cost.estimated`,
        response.usage.estimatedCost,
        { model: response.model, ...this.config.labels }
      );
    }

    // Finish reason
    this.metrics.increment(
      `${this.config.prefix}.finish_reason`,
      {
        reason: response.finishReason,
        model: response.model,
        ...this.config.labels,
      }
    );
  }

  recordError(error: LLMError, durationMs: number): void {
    this.metrics.increment(
      `${this.config.prefix}.errors.total`,
      {
        error_type: error.type,
        retryable: error.retryable.toString(),
        ...this.config.labels,
      }
    );

    this.metrics.histogram(
      `${this.config.prefix}.errors.duration_ms`,
      durationMs,
      {
        error_type: error.type,
        ...this.config.labels,
      }
    );
  }

  recordCircuitBreakerState(state: CircuitState): void {
    const stateValue =
      state === CircuitState.CLOSED ? 0 :
      state === CircuitState.HALF_OPEN ? 1 : 2;

    this.metrics.gauge(
      `${this.config.prefix}.circuit_breaker.state`,
      stateValue,
      this.config.labels
    );
  }

  recordRateLimitWait(waitMs: number, limitType: 'requests' | 'tokens'): void {
    this.metrics.histogram(
      `${this.config.prefix}.rate_limit.wait_ms`,
      waitMs,
      {
        limit_type: limitType,
        ...this.config.labels,
      }
    );
  }
}
```

### 9.3 Distributed Tracing

```typescript
/**
 * Tracing interface
 */
interface ITracer {
  startSpan(name: string, context?: any): ISpan;
}

interface ISpan {
  setTag(key: string, value: any): void;
  log(event: string, payload?: any): void;
  finish(): void;
  context(): any;
}

/**
 * LLM Client tracer
 */
class LLMClientTracer {
  private tracer: ITracer;
  private config: TracingConfig;

  constructor(tracer: ITracer, config: TracingConfig) {
    this.tracer = tracer;
    this.config = config;
  }

  traceRequest(
    request: LLMRequest,
    parentContext?: any
  ): ISpan {
    const span = this.tracer.startSpan('llm.request', parentContext);

    span.setTag('llm.provider', 'openai'); // From config
    span.setTag('llm.model', request.model);
    span.setTag('llm.request_id', request.id);
    span.setTag('llm.temperature', request.temperature);
    span.setTag('llm.max_tokens', request.maxTokens);

    return span;
  }

  traceResponse(span: ISpan, response: LLMResponse): void {
    span.setTag('llm.response_id', response.id);
    span.setTag('llm.finish_reason', response.finishReason);
    span.setTag('llm.prompt_tokens', response.usage.promptTokens);
    span.setTag('llm.completion_tokens', response.usage.completionTokens);
    span.setTag('llm.total_tokens', response.usage.totalTokens);

    if (response.usage.estimatedCost) {
      span.setTag('llm.estimated_cost', response.usage.estimatedCost);
    }
  }

  traceError(span: ISpan, error: LLMError): void {
    span.setTag('error', true);
    span.setTag('error.type', error.type);
    span.setTag('error.message', error.message);
    span.setTag('error.retryable', error.retryable);

    if (error.statusCode) {
      span.setTag('http.status_code', error.statusCode);
    }

    span.log('error', {
      type: error.type,
      message: error.message,
      stack: error.stack,
    });
  }
}
```

---

## 10. Testing Strategy

### 10.1 Unit Testing

```typescript
/**
 * Mock LLM Provider for testing
 */
class MockLLMProvider implements ILLMProvider {
  readonly name = 'mock';
  readonly version = '1.0.0';
  readonly capabilities: ProviderCapabilities = {
    streaming: true,
    functionCalling: true,
    vision: false,
  };

  private responses: Map<string, CompletionResponse> = new Map();
  private errors: Map<string, Error> = new Map();

  constructor() {}

  setResponse(requestId: string, response: CompletionResponse): void {
    this.responses.set(requestId, response);
  }

  setError(requestId: string, error: Error): void {
    this.errors.set(requestId, error);
  }

  async complete(request: CompletionRequest): Promise<CompletionResponse> {
    const key = this.getRequestKey(request);

    if (this.errors.has(key)) {
      throw this.errors.get(key);
    }

    if (this.responses.has(key)) {
      return this.responses.get(key)!;
    }

    // Default response
    return {
      id: 'mock-response-id',
      requestId: request.id,
      timestamp: new Date().toISOString(),
      model: request.model,
      content: 'Mock response',
      role: 'assistant',
      finishReason: 'stop',
      usage: {
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      },
    };
  }

  async *stream(
    request: CompletionRequest
  ): AsyncIterableIterator<CompletionChunk> {
    yield {
      id: 'mock-chunk-1',
      delta: { role: 'assistant', content: 'Mock ' },
    };
    yield {
      id: 'mock-chunk-2',
      delta: { content: 'streaming ' },
    };
    yield {
      id: 'mock-chunk-3',
      delta: { content: 'response' },
      finishReason: 'stop',
    };
  }

  async embeddings(request: EmbeddingRequest): Promise<EmbeddingResponse> {
    return {
      embeddings: [[0.1, 0.2, 0.3]],
      usage: {
        promptTokens: 10,
        totalTokens: 10,
      },
    };
  }

  async validateApiKey(): Promise<boolean> {
    return true;
  }

  async getModels(): Promise<ModelInfo[]> {
    return [
      { id: 'mock-model-1', name: 'Mock Model 1' },
    ];
  }

  estimateCost(request: CompletionRequest): CostEstimate {
    return {
      estimatedCost: 0.001,
      currency: 'USD',
    };
  }

  private getRequestKey(request: CompletionRequest): string {
    return request.id || JSON.stringify(request.messages);
  }
}

/**
 * Example unit tests
 */
describe('SentinelLLMClient', () => {
  let client: SentinelLLMClient;
  let mockProvider: MockLLMProvider;
  let mockLogger: jest.Mocked<ILogger>;
  let mockMetrics: jest.Mocked<IMetrics>;

  beforeEach(() => {
    mockProvider = new MockLLMProvider();
    mockLogger = createMockLogger();
    mockMetrics = createMockMetrics();

    const config: SentinelLLMConfig = {
      clientId: 'test-sentinel',
      clientName: 'Test Sentinel Client',
      version: '1.0.0',
      provider: {
        provider: 'mock',
        apiKey: 'test-key',
        defaultModel: 'mock-model',
        availableModels: ['mock-model'],
        defaultTemperature: 0.7,
        defaultMaxTokens: 2048,
        defaultTopP: 1.0,
      },
      resilience: createDefaultResilienceConfig(),
      observability: createDefaultObservabilityConfig(),
      features: createDefaultFeatureConfig(),
      environment: 'test',
    };

    client = new SentinelLLMClient(config);
    client['provider'] = mockProvider; // Inject mock
  });

  describe('analyzeAnomaly', () => {
    it('should analyze anomaly and return classification', async () => {
      const event: AnomalyEvent = {
        eventId: 'test-event-1',
        timestamp: '2025-11-12T00:00:00Z',
        source: 'test-source',
        metrics: {
          cpu_usage: 95,
          memory_usage: 85,
        },
        context: {},
      };

      const mockResponse: CompletionResponse = {
        id: 'response-1',
        requestId: 'request-1',
        timestamp: '2025-11-12T00:00:01Z',
        model: 'mock-model',
        content: JSON.stringify({
          isAnomaly: true,
          confidence: 0.95,
          severity: 'P1',
          rootCause: 'High CPU usage',
          recommendations: ['Scale up resources'],
        }),
        role: 'assistant',
        finishReason: 'stop',
        usage: {
          promptTokens: 150,
          completionTokens: 75,
          totalTokens: 225,
        },
      };

      mockProvider.setResponse('request-1', mockResponse);

      const analysis = await client.analyzeAnomaly(event);

      expect(analysis.isAnomaly).toBe(true);
      expect(analysis.confidence).toBe(0.95);
      expect(analysis.severity).toBe('P1');
      expect(analysis.recommendations).toContain('Scale up resources');
    });

    it('should retry on transient errors', async () => {
      const event: AnomalyEvent = {
        eventId: 'test-event-2',
        timestamp: '2025-11-12T00:00:00Z',
        source: 'test-source',
        metrics: { error_rate: 10 },
        context: {},
      };

      // First attempt fails with rate limit
      mockProvider.setError(
        'request-1',
        new LLMError(LLMErrorType.RATE_LIMIT, 'Rate limit', 429, true)
      );

      // Second attempt succeeds
      const mockResponse: CompletionResponse = {
        id: 'response-2',
        requestId: 'request-2',
        timestamp: '2025-11-12T00:00:02Z',
        model: 'mock-model',
        content: JSON.stringify({
          isAnomaly: false,
          confidence: 0.6,
          severity: 'P4',
        }),
        role: 'assistant',
        finishReason: 'stop',
        usage: {
          promptTokens: 100,
          completionTokens: 50,
          totalTokens: 150,
        },
      };

      mockProvider.setResponse('request-2', mockResponse);

      const analysis = await client.analyzeAnomaly(event);

      expect(analysis.isAnomaly).toBe(false);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Retrying')
      );
    });
  });
});
```

### 10.2 Integration Testing

```typescript
/**
 * Integration test suite
 */
describe('LLM Client Integration Tests', () => {
  let client: SentinelLLMClient;

  beforeAll(() => {
    // Use real provider in integration tests
    const config = ConfigLoader.load('test');
    client = new SentinelLLMClient(config);
  });

  it('should successfully call real LLM provider', async () => {
    const event: AnomalyEvent = {
      eventId: 'integration-test-1',
      timestamp: new Date().toISOString(),
      source: 'integration-test',
      metrics: {
        latency_ms: 5000,
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
  }, 30000); // 30s timeout for real API call

  it('should handle rate limiting gracefully', async () => {
    // Send multiple requests rapidly
    const promises = Array.from({ length: 100 }, (_, i) =>
      client.analyzeAnomaly({
        eventId: `rate-limit-test-${i}`,
        timestamp: new Date().toISOString(),
        source: 'rate-limit-test',
        metrics: { value: i },
        context: {},
      })
    );

    const results = await Promise.allSettled(promises);

    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    // Some should succeed, rate limiting should prevent all from failing
    expect(successful).toBeGreaterThan(0);

    // Check that rate limit errors are properly categorized
    const rateLimitErrors = results
      .filter(r => r.status === 'rejected')
      .filter(r => (r as PromiseRejectedResult).reason.type === LLMErrorType.RATE_LIMIT);

    expect(rateLimitErrors.length).toBeGreaterThan(0);
  }, 60000);
});
```

### 10.3 Load Testing

```typescript
/**
 * Load test configuration
 */
interface LoadTestConfig {
  durationSeconds: number;
  requestsPerSecond: number;
  concurrentRequests: number;
}

/**
 * Load tester for LLM clients
 */
class LLMClientLoadTester {
  private client: BaseLLMClient;
  private metrics: LoadTestMetrics;

  constructor(client: BaseLLMClient) {
    this.client = client;
    this.metrics = new LoadTestMetrics();
  }

  async runLoadTest(config: LoadTestConfig): Promise<LoadTestReport> {
    const startTime = Date.now();
    const endTime = startTime + (config.durationSeconds * 1000);

    const workers: Promise<void>[] = [];

    // Start workers
    for (let i = 0; i < config.concurrentRequests; i++) {
      workers.push(this.worker(endTime, config.requestsPerSecond));
    }

    // Wait for all workers to complete
    await Promise.all(workers);

    return this.metrics.generateReport();
  }

  private async worker(endTime: number, rps: number): Promise<void> {
    const delayMs = 1000 / rps;

    while (Date.now() < endTime) {
      const startTime = Date.now();

      try {
        await this.sendRequest();
        this.metrics.recordSuccess(Date.now() - startTime);
      } catch (error) {
        this.metrics.recordFailure(Date.now() - startTime, error as Error);
      }

      // Wait before next request
      const elapsed = Date.now() - startTime;
      const waitTime = Math.max(0, delayMs - elapsed);
      await this.delay(waitTime);
    }
  }

  private async sendRequest(): Promise<void> {
    // Send test request
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Load test metrics collector
 */
class LoadTestMetrics {
  private successCount = 0;
  private failureCount = 0;
  private latencies: number[] = [];
  private errors: Map<string, number> = new Map();

  recordSuccess(latencyMs: number): void {
    this.successCount++;
    this.latencies.push(latencyMs);
  }

  recordFailure(latencyMs: number, error: Error): void {
    this.failureCount++;
    this.latencies.push(latencyMs);

    const errorType = error.constructor.name;
    this.errors.set(errorType, (this.errors.get(errorType) || 0) + 1);
  }

  generateReport(): LoadTestReport {
    const sortedLatencies = this.latencies.sort((a, b) => a - b);

    return {
      totalRequests: this.successCount + this.failureCount,
      successCount: this.successCount,
      failureCount: this.failureCount,
      successRate: this.successCount / (this.successCount + this.failureCount),
      latency: {
        min: Math.min(...sortedLatencies),
        max: Math.max(...sortedLatencies),
        mean: sortedLatencies.reduce((a, b) => a + b, 0) / sortedLatencies.length,
        p50: this.percentile(sortedLatencies, 0.5),
        p95: this.percentile(sortedLatencies, 0.95),
        p99: this.percentile(sortedLatencies, 0.99),
      },
      errors: Object.fromEntries(this.errors),
    };
  }

  private percentile(sorted: number[], p: number): number {
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[index];
  }
}

interface LoadTestReport {
  totalRequests: number;
  successCount: number;
  failureCount: number;
  successRate: number;
  latency: {
    min: number;
    max: number;
    mean: number;
    p50: number;
    p95: number;
    p99: number;
  };
  errors: Record<string, number>;
}
```

---

## 11. Example Usage Patterns

### 11.1 Basic Usage

```typescript
/**
 * Example 1: Basic Sentinel client usage
 */
async function exampleSentinelBasicUsage() {
  // Load configuration
  const config = ConfigLoader.load('production');

  // Create client
  const sentinelClient = new SentinelLLMClient(config);

  // Analyze anomaly
  const event: AnomalyEvent = {
    eventId: 'evt-001',
    timestamp: '2025-11-12T10:00:00Z',
    source: 'monitoring-system',
    metrics: {
      cpu_usage: 95,
      memory_usage: 85,
      disk_io: 1000,
      network_latency: 500,
    },
    context: {
      service: 'api-gateway',
      environment: 'production',
      region: 'us-east-1',
    },
  };

  try {
    const analysis = await sentinelClient.analyzeAnomaly(event);

    console.log('Anomaly Analysis:', {
      isAnomaly: analysis.isAnomaly,
      confidence: analysis.confidence,
      severity: analysis.severity,
      rootCause: analysis.rootCause,
      recommendations: analysis.recommendations,
    });

    // Take action based on analysis
    if (analysis.isAnomaly && analysis.severity === 'P0') {
      await createIncident(analysis);
    }
  } catch (error) {
    if (error instanceof LLMError) {
      console.error('LLM Error:', {
        type: error.type,
        message: error.message,
        retryable: error.retryable,
      });

      if (error.retryable) {
        // Retry logic is handled automatically
      }
    } else {
      console.error('Unexpected error:', error);
    }
  }
}

/**
 * Example 2: Shield client for threat analysis
 */
async function exampleShieldThreatAnalysis() {
  const config = ConfigLoader.load('production');
  const shieldClient = new ShieldLLMClient(config);

  const securityEvent: SecurityEvent = {
    eventId: 'sec-evt-001',
    timestamp: '2025-11-12T10:05:00Z',
    eventType: 'suspicious_activity',
    payload: 'SELECT * FROM users WHERE id=1 OR 1=1--',
    context: {
      userId: 'user-123',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0...',
      requestPath: '/api/users/search',
    },
  };

  const threatAnalysis = await shieldClient.analyzeThreat(securityEvent);

  if (threatAnalysis.isThreat) {
    console.log('Threat Detected:', {
      threatLevel: threatAnalysis.threatLevel,
      confidence: threatAnalysis.confidence,
      threatTypes: threatAnalysis.threatType,
      indicators: threatAnalysis.indicators,
      mitigationSteps: threatAnalysis.mitigationSteps,
    });

    // Execute mitigation
    for (const step of threatAnalysis.mitigationSteps) {
      await executeMitigationStep(step);
    }
  }
}

/**
 * Example 3: Edge-Agent client with fallback
 */
async function exampleEdgeAgentProcessing() {
  const config = ConfigLoader.load('production');
  const edgeClient = new EdgeAgentLLMClient(config);

  const inferenceRequest: InferenceRequest = {
    requestId: 'edge-req-001',
    model: 'gpt-3.5-turbo',
    input: 'Analyze this log entry for errors',
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
  };

  const result = await edgeClient.processLocalInference(inferenceRequest);

  if (result.processedLocally) {
    console.log('Processed locally:', result.result);
  } else if (result.fallbackToCentral) {
    console.log('Fell back to central processing:', result.result);
  }
}

/**
 * Example 4: Governance client for compliance checking
 */
async function exampleGovernanceCompliance() {
  const config = ConfigLoader.load('production');
  const governanceClient = new GovernanceLLMClient(config);

  const complianceRequest: ComplianceRequest = {
    requestId: 'comp-req-001',
    action: 'process_user_data',
    context: {
      userId: 'user-456',
      tenantId: 'tenant-789',
      environment: 'production',
      dataClassification: 'PII',
    },
    policies: ['gdpr', 'hipaa', 'internal-data-policy'],
  };

  const complianceResult = await governanceClient.validateCompliance(
    complianceRequest
  );

  if (!complianceResult.compliant) {
    console.error('Compliance violations:', complianceResult.violations);

    for (const violation of complianceResult.violations) {
      console.error(`- ${violation.policyName}: ${violation.description}`);
      console.error(`  Remediation: ${violation.remediation}`);
    }

    throw new Error('Compliance check failed');
  }

  console.log('Compliance check passed');
}
```

### 11.2 Advanced Patterns

```typescript
/**
 * Example 5: Batch processing with concurrent requests
 */
async function exampleBatchProcessing() {
  const config = ConfigLoader.load('production');
  const sentinelClient = new SentinelLLMClient(config);

  const events: AnomalyEvent[] = [
    // ... array of events
  ];

  // Process in batches to respect rate limits
  const batchSize = 10;
  const results: AnomalyAnalysis[] = [];

  for (let i = 0; i < events.length; i += batchSize) {
    const batch = events.slice(i, i + batchSize);

    const batchResults = await Promise.all(
      batch.map(event => sentinelClient.analyzeAnomaly(event))
    );

    results.push(...batchResults);

    // Wait between batches if needed
    if (i + batchSize < events.length) {
      await delay(1000);
    }
  }

  return results;
}

/**
 * Example 6: Streaming responses
 */
async function exampleStreamingResponse() {
  const config = ConfigLoader.load('production');
  const client = new SentinelLLMClient(config);

  // Enable streaming in request
  const request: LLMRequest = {
    id: 'stream-req-001',
    timestamp: new Date().toISOString(),
    model: 'gpt-4',
    messages: [
      {
        role: 'user',
        content: 'Provide a detailed analysis of this incident...',
      },
    ],
    temperature: 0.7,
    maxTokens: 4096,
  };

  console.log('Starting streaming response...');

  for await (const chunk of client.streamResponse(request)) {
    process.stdout.write(chunk.delta.content || '');

    if (chunk.finishReason) {
      console.log(`\nFinished: ${chunk.finishReason}`);
    }
  }
}

/**
 * Example 7: Custom middleware
 */
class RequestLoggingMiddleware implements IMiddleware {
  readonly name = 'request-logging';
  readonly priority = 10;

  private logger: ILogger;

  constructor(logger: ILogger) {
    this.logger = logger;
  }

  async onRequest(
    request: LLMRequest,
    context: RequestContext
  ): Promise<LLMRequest> {
    this.logger.info('Request started', {
      requestId: request.id,
      model: request.model,
      timestamp: request.timestamp,
    });

    return request;
  }

  async onResponse(
    response: LLMResponse,
    context: RequestContext
  ): Promise<LLMResponse> {
    this.logger.info('Request completed', {
      requestId: response.requestId,
      responseId: response.id,
      durationMs: Date.now() - context.startTime,
    });

    return response;
  }

  async onError(error: Error, context: RequestContext): Promise<void> {
    this.logger.error('Request failed', {
      requestId: context.requestId,
      error: error.message,
      durationMs: Date.now() - context.startTime,
    });
  }
}

// Usage
const config = ConfigLoader.load('production');
const client = new SentinelLLMClient(config);
client.use(new RequestLoggingMiddleware(logger));

/**
 * Example 8: Multi-provider fallback
 */
class MultiProviderLLMClient {
  private providers: BaseLLMClient[];

  constructor(providers: BaseLLMClient[]) {
    this.providers = providers;
  }

  async complete(request: LLMRequest): Promise<LLMResponse> {
    let lastError: Error;

    for (const provider of this.providers) {
      try {
        return await provider.executeRequest(request);
      } catch (error) {
        lastError = error as Error;
        console.warn(`Provider ${provider.name} failed, trying next...`);
      }
    }

    throw lastError!;
  }
}

// Usage
const primaryClient = new SentinelLLMClient(configOpenAI);
const fallbackClient = new SentinelLLMClient(configAnthropic);
const multiProvider = new MultiProviderLLMClient([primaryClient, fallbackClient]);
```

---

## 12. Security Considerations

### 12.1 API Key Management

```typescript
/**
 * Secure API key storage and rotation
 */
class SecureKeyManager {
  private keyStore: IKeyStore;
  private rotationPolicy: KeyRotationPolicy;

  constructor(keyStore: IKeyStore, rotationPolicy: KeyRotationPolicy) {
    this.keyStore = keyStore;
    this.rotationPolicy = rotationPolicy;
  }

  async getApiKey(provider: string): Promise<string> {
    const key = await this.keyStore.retrieve(provider);

    if (this.shouldRotate(key)) {
      await this.rotateKey(provider);
      return await this.keyStore.retrieve(provider);
    }

    return key.value;
  }

  private shouldRotate(key: ApiKey): boolean {
    const age = Date.now() - key.createdAt;
    return age > this.rotationPolicy.maxAgeMs;
  }

  private async rotateKey(provider: string): Promise<void> {
    // Implement key rotation logic
  }
}

interface IKeyStore {
  retrieve(provider: string): Promise<ApiKey>;
  store(provider: string, key: string): Promise<void>;
  delete(provider: string): Promise<void>;
}

interface ApiKey {
  value: string;
  createdAt: number;
  expiresAt?: number;
}

interface KeyRotationPolicy {
  maxAgeMs: number;
  rotationWarningMs: number;
}
```

### 12.2 Request Validation & Sanitization

```typescript
/**
 * Request validator with input sanitization
 */
class RequestValidator {
  private contentFilter: IContentFilter;
  private schemaValidator: ISchemaValidator;

  constructor(contentFilter: IContentFilter, schemaValidator: ISchemaValidator) {
    this.contentFilter = contentFilter;
    this.schemaValidator = schemaValidator;
  }

  async validate(request: LLMRequest): Promise<ValidationResult> {
    const errors: string[] = [];

    // Schema validation
    if (!this.schemaValidator.validate(request)) {
      errors.push('Invalid request schema');
    }

    // Content filtering
    for (const message of request.messages) {
      if (typeof message.content === 'string') {
        if (await this.contentFilter.containsMaliciousContent(message.content)) {
          errors.push('Potentially malicious content detected');
        }
      }
    }

    // Size validation
    const requestSize = JSON.stringify(request).length;
    if (requestSize > 1000000) { // 1MB
      errors.push('Request size exceeds maximum allowed');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
}
```

### 12.3 PII Detection & Redaction

```typescript
/**
 * PII detector and redactor
 */
class PIIRedactor {
  private patterns: Map<string, RegExp>;

  constructor() {
    this.patterns = new Map([
      ['email', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g],
      ['phone', /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g],
      ['ssn', /\b\d{3}-\d{2}-\d{4}\b/g],
      ['credit_card', /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g],
      ['api_key', /\b[A-Za-z0-9]{32,}\b/g],
    ]);
  }

  redact(text: string): RedactionResult {
    let redactedText = text;
    const findings: PIIFinding[] = [];

    for (const [type, pattern] of this.patterns) {
      const matches = text.match(pattern);

      if (matches) {
        findings.push({
          type,
          count: matches.length,
          positions: this.findPositions(text, pattern),
        });

        redactedText = redactedText.replace(pattern, `[REDACTED_${type.toUpperCase()}]`);
      }
    }

    return {
      original: text,
      redacted: redactedText,
      findings,
      containsPII: findings.length > 0,
    };
  }

  private findPositions(text: string, pattern: RegExp): number[] {
    const positions: number[] = [];
    let match;

    while ((match = pattern.exec(text)) !== null) {
      positions.push(match.index);
    }

    return positions;
  }
}

interface PIIFinding {
  type: string;
  count: number;
  positions: number[];
}

interface RedactionResult {
  original: string;
  redacted: string;
  findings: PIIFinding[];
  containsPII: boolean;
}
```

---

## 13. Performance Guidelines

### 13.1 Optimization Strategies

```typescript
/**
 * Response caching for identical requests
 */
class LLMResponseCache {
  private cache: Map<string, CacheEntry>;
  private ttlMs: number;

  constructor(ttlMs: number = 3600000) { // 1 hour default
    this.cache = new Map();
    this.ttlMs = ttlMs;

    // Cleanup expired entries every 5 minutes
    setInterval(() => this.cleanup(), 300000);
  }

  async get(request: LLMRequest): Promise<LLMResponse | null> {
    const key = this.generateKey(request);
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return null;
    }

    return entry.response;
  }

  async set(request: LLMRequest, response: LLMResponse): Promise<void> {
    const key = this.generateKey(request);

    this.cache.set(key, {
      response,
      timestamp: Date.now(),
    });
  }

  private generateKey(request: LLMRequest): string {
    // Generate deterministic cache key
    const normalized = {
      model: request.model,
      messages: request.messages,
      temperature: request.temperature,
      maxTokens: request.maxTokens,
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(normalized))
      .digest('hex');
  }

  private cleanup(): void {
    const now = Date.now();

    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.ttlMs) {
        this.cache.delete(key);
      }
    }
  }
}

interface CacheEntry {
  response: LLMResponse;
  timestamp: number;
}
```

### 13.2 Connection Pooling

```typescript
/**
 * Connection pool for HTTP clients
 */
class ConnectionPool {
  private pool: http.Agent | https.Agent;

  constructor(options: ConnectionPoolOptions) {
    this.pool = new https.Agent({
      keepAlive: true,
      keepAliveMsecs: options.keepAliveMs || 60000,
      maxSockets: options.maxConnections || 100,
      maxFreeSockets: options.maxIdleConnections || 10,
      timeout: options.timeoutMs || 30000,
    });
  }

  getAgent(): http.Agent | https.Agent {
    return this.pool;
  }

  destroy(): void {
    this.pool.destroy();
  }
}

interface ConnectionPoolOptions {
  keepAliveMs?: number;
  maxConnections?: number;
  maxIdleConnections?: number;
  timeoutMs?: number;
}
```

---

## 14. Migration & Deployment

### 14.1 Migration Strategy

```typescript
/**
 * Feature flag-based migration
 */
class LLMClientMigrator {
  private oldClient: BaseLLMClient;
  private newClient: BaseLLMClient;
  private featureFlag: IFeatureFlag;

  constructor(
    oldClient: BaseLLMClient,
    newClient: BaseLLMClient,
    featureFlag: IFeatureFlag
  ) {
    this.oldClient = oldClient;
    this.newClient = newClient;
    this.featureFlag = featureFlag;
  }

  async execute(request: LLMRequest): Promise<LLMResponse> {
    const useNewClient = await this.featureFlag.isEnabled(
      'use_new_llm_client',
      { userId: request.metadata?.userId }
    );

    if (useNewClient) {
      try {
        return await this.newClient.executeRequest(request);
      } catch (error) {
        // Fallback to old client on error
        console.error('New client failed, falling back to old client', error);
        return await this.oldClient.executeRequest(request);
      }
    } else {
      return await this.oldClient.executeRequest(request);
    }
  }
}
```

### 14.2 Deployment Checklist

- [ ] Configure environment-specific settings
- [ ] Set up secure API key storage (AWS Secrets Manager, Vault, etc.)
- [ ] Configure observability endpoints (metrics, logs, traces)
- [ ] Set up monitoring and alerting
- [ ] Test rate limiting and circuit breaker behavior
- [ ] Verify retry logic with chaos testing
- [ ] Benchmark performance under load
- [ ] Set up cost tracking and budgets
- [ ] Configure PII redaction policies
- [ ] Review and approve security scan results
- [ ] Set up feature flags for gradual rollout
- [ ] Prepare rollback procedures
- [ ] Document runbook for common issues
- [ ] Schedule on-call rotation
- [ ] Plan capacity for expected load

---

## Appendix A: Glossary

- **Circuit Breaker**: A design pattern that prevents cascading failures by stopping requests to a failing service
- **Exponential Backoff**: A retry strategy that increases the delay between retries exponentially
- **PII**: Personally Identifiable Information
- **Rate Limiting**: Controlling the rate of requests to prevent overload
- **Token Bucket**: An algorithm for rate limiting that uses tokens to represent capacity
- **Observability**: The ability to understand system state through logs, metrics, and traces

---

## Appendix B: Reference Architecture

### File Structure

```
src/
├── clients/
│   ├── base/
│   │   ├── BaseLLMClient.ts
│   │   ├── RequestContext.ts
│   │   └── types.ts
│   ├── sentinel/
│   │   ├── SentinelLLMClient.ts
│   │   ├── types.ts
│   │   └── prompts.ts
│   ├── shield/
│   │   ├── ShieldLLMClient.ts
│   │   ├── types.ts
│   │   └── prompts.ts
│   ├── edge-agent/
│   │   ├── EdgeAgentLLMClient.ts
│   │   ├── types.ts
│   │   └── prompts.ts
│   └── governance/
│       ├── GovernanceLLMClient.ts
│       ├── types.ts
│       └── prompts.ts
├── providers/
│   ├── ILLMProvider.ts
│   ├── OpenAIProvider.ts
│   ├── AnthropicProvider.ts
│   ├── AzureOpenAIProvider.ts
│   ├── VertexAIProvider.ts
│   └── ProviderFactory.ts
├── resilience/
│   ├── RetryManager.ts
│   ├── CircuitBreaker.ts
│   ├── RateLimiter.ts
│   └── TimeoutManager.ts
├── observability/
│   ├── Logger.ts
│   ├── Metrics.ts
│   ├── Tracer.ts
│   └── AuditLogger.ts
├── middleware/
│   ├── IMiddleware.ts
│   ├── MiddlewareChain.ts
│   └── implementations/
│       ├── LoggingMiddleware.ts
│       ├── MetricsMiddleware.ts
│       └── ValidationMiddleware.ts
├── config/
│   ├── ConfigLoader.ts
│   ├── types.ts
│   └── environments/
│       ├── production.json
│       ├── staging.json
│       └── development.json
├── errors/
│   ├── LLMError.ts
│   ├── ErrorHandler.ts
│   └── ErrorCategorizer.ts
├── security/
│   ├── PIIRedactor.ts
│   ├── RequestValidator.ts
│   └── KeyManager.ts
└── utils/
    ├── Cache.ts
    ├── ConnectionPool.ts
    └── helpers.ts
```

---

**End of Architecture Specification**

This architecture provides a solid foundation for implementing enterprise-grade LLM clients with production-ready resilience, observability, and security features. The implementation team can use this specification as a comprehensive guide for development.
