// corporate-bedrock-client.ts
/**
 * Corporate Bedrock Client for Node.js/TypeScript
 * Ensures all Claude API calls go through corporate proxy infrastructure
 */

import axios, { AxiosInstance, AxiosResponse, AxiosRequestConfig } from 'axios';
import { EventEmitter } from 'events';

export interface BedrockMessage {
  role: 'user' | 'assistant' | 'system';
  content: string | Array<{
    type: 'text';
    text: string;
  }>;
}

export interface BedrockInvokeRequest {
  modelId: string;
  messages: BedrockMessage[];
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  system?: string;
  stopSequences?: string[];
}

export interface BedrockInvokeResponse {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
  stop_reason: string;
}

export interface UsageMetrics {
  user_id: string;
  department: string;
  total_requests: number;
  total_tokens: number;
  total_cost: number;
  period_start: string;
  period_end: string;
  models_used: Array<{
    model_id: string;
    requests: number;
    tokens: number;
    cost: number;
  }>;
}

export interface CorporateBedrockConfig {
  proxyEndpoint?: string;
  apiKey?: string;
  userId?: string;
  department?: string;
  timeout?: number;
  corporateProxyUrl?: string;
}

export class CorporateBedrockError extends Error {
  constructor(message: string, public statusCode?: number) {
    super(message);
    this.name = 'CorporateBedrockError';
  }
}

export class RateLimitError extends CorporateBedrockError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429);
    this.name = 'RateLimitError';
  }
}

export class CorporateBedrockClient {
  private httpClient: AxiosInstance;
  private config: Required<CorporateBedrockConfig>;

  constructor(config: CorporateBedrockConfig = {}) {
    // Load configuration from environment variables and provided config
    this.config = {
      proxyEndpoint: config.proxyEndpoint || process.env.BEDROCK_PROXY_ENDPOINT || '',
      apiKey: config.apiKey || process.env.BEDROCK_API_KEY || '',
      userId: config.userId || process.env.USER_ID || 'unknown',
      department: config.department || process.env.DEPARTMENT || 'engineering',
      timeout: config.timeout || parseInt(process.env.BEDROCK_TIMEOUT || '300') * 1000,
      corporateProxyUrl: config.corporateProxyUrl || process.env.CORPORATE_PROXY_URL || ''
    };

    if (!this.config.proxyEndpoint) {
      throw new CorporateBedrockError('BEDROCK_PROXY_ENDPOINT must be provided or set as environment variable');
    }

    if (!this.config.apiKey) {
      throw new CorporateBedrockError('BEDROCK_API_KEY must be provided or set as environment variable');
    }

    // Configure HTTP client
    const axiosConfig: AxiosRequestConfig = {
      baseURL: this.config.proxyEndpoint,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.config.apiKey,
        'X-User-ID': this.config.userId,
        'X-Department': this.config.department,
        'User-Agent': `CorporateBedrockClient-NodeJS/1.0 (${this.config.userId})`
      }
    };

    // Configure corporate proxy if provided
    if (this.config.corporateProxyUrl) {
      const proxyUrl = new URL(this.config.corporateProxyUrl);
      axiosConfig.proxy = {
        host: proxyUrl.hostname,
        port: parseInt(proxyUrl.port) || 8080,
        protocol: proxyUrl.protocol.slice(0, -1) as 'http' | 'https'
      };
    }

    this.httpClient = axios.create(axiosConfig);

    // Add request/response interceptors for logging and error handling
    this.setupInterceptors();

    console.log(`Initialized Corporate Bedrock Client for user ${this.config.userId}`);
  }

  private setupInterceptors(): void {
    // Request interceptor for logging
    this.httpClient.interceptors.request.use(
      (config) => {
        console.log(`Corporate Bedrock request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        console.error('Request interceptor error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.httpClient.interceptors.response.use(
      (response) => {
        console.log(`Corporate Bedrock response: ${response.status} - ${response.config.url}`);
        return response;
      },
      (error) => {
        if (error.response) {
          const { status, data } = error.response;
          
          if (status === 429) {
            throw new RateLimitError(data?.error?.message || 'Rate limit exceeded');
          }
          
          throw new CorporateBedrockError(
            data?.error?.message || `Request failed with status ${status}`,
            status
          );
        } else if (error.request) {
          throw new CorporateBedrockError('No response received from server');
        } else {
          throw new CorporateBedrockError(`Request configuration error: ${error.message}`);
        }
      }
    );
  }

  /**
   * Invoke a Claude model through the corporate proxy
   */
  async invokeModel(request: BedrockInvokeRequest): Promise<BedrockInvokeResponse> {
    // Validate model ID
    if (!request.modelId.startsWith('anthropic.claude')) {
      throw new CorporateBedrockError(`Unsupported model ID: ${request.modelId}. Only Claude models are allowed.`);
    }

    // Construct request payload
    const payload = {
      modelId: request.modelId,
      messages: request.messages,
      inferenceConfig: {
        maxTokens: request.maxTokens || 4096,
        temperature: request.temperature || 0.7,
        topP: request.topP || 0.9,
        ...(request.stopSequences && { stopSequences: request.stopSequences })
      },
      ...(request.system && { system: request.system })
    };

    try {
      const response: AxiosResponse<BedrockInvokeResponse> = await this.httpClient.post(
        `/model/${request.modelId}/invoke`,
        payload
      );

      return response.data;
    } catch (error) {
      console.error('Bedrock invoke error:', error);
      throw error;
    }
  }

  /**
   * Invoke a Claude model with streaming response
   */
  async invokeModelWithResponseStream(request: BedrockInvokeRequest): Promise<EventEmitter> {
    // Validate model ID
    if (!request.modelId.startsWith('anthropic.claude')) {
      throw new CorporateBedrockError(`Unsupported model ID: ${request.modelId}. Only Claude models are allowed.`);
    }

    const emitter = new EventEmitter();

    // Construct request payload
    const payload = {
      modelId: request.modelId,
      messages: request.messages,
      inferenceConfig: {
        maxTokens: request.maxTokens || 4096,
        temperature: request.temperature || 0.7,
        topP: request.topP || 0.9,
        ...(request.stopSequences && { stopSequences: request.stopSequences })
      },
      ...(request.system && { system: request.system })
    };

    try {
      const response = await this.httpClient.post(
        `/model/${request.modelId}/invoke-with-response-stream`,
        payload,
        {
          responseType: 'stream'
        }
      );

      response.data.on('data', (chunk: Buffer) => {
        const lines = chunk.toString().split('\n');
        
        for (const line of lines) {
          if (line.trim()) {
            try {
              const data = JSON.parse(line);
              emitter.emit('data', data);
            } catch (parseError) {
              console.warn('Failed to parse streaming response line:', line);
            }
          }
        }
      });

      response.data.on('end', () => {
        emitter.emit('end');
      });

      response.data.on('error', (error: Error) => {
        emitter.emit('error', new CorporateBedrockError(`Streaming error: ${error.message}`));
      });

    } catch (error) {
      console.error('Bedrock streaming invoke error:', error);
      emitter.emit('error', error);
    }

    return emitter;
  }

  /**
   * Get usage metrics for the current user
   */
  async getUsageMetrics(startDate?: string, endDate?: string): Promise<UsageMetrics> {
    const params: Record<string, string> = {};
    if (startDate) params.start_date = startDate;
    if (endDate) params.end_date = endDate;

    try {
      const response: AxiosResponse<UsageMetrics> = await this.httpClient.get('/usage/metrics', {
        params
      });

      return response.data;
    } catch (error) {
      console.error('Usage metrics error:', error);
      throw error;
    }
  }

  /**
   * Health check for the corporate proxy
   */
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      const response = await this.httpClient.get('/health');
      return response.data;
    } catch (error) {
      console.error('Health check error:', error);
      throw error;
    }
  }
}

/**
 * AWS SDK Interceptor to route Bedrock calls through corporate proxy
 */
export class AWSBedrockInterceptor {
  private static originalAWS: any = null;
  private corporateClient: CorporateBedrockClient;

  constructor(corporateClient: CorporateBedrockClient) {
    this.corporateClient = corporateClient;
  }

  /**
   * Apply interceptor to AWS SDK to route Bedrock calls through corporate proxy
   */
  static applyInterceptor(corporateClient: CorporateBedrockClient): void {
    try {
      // Dynamic import to handle cases where AWS SDK might not be installed
      const AWS = require('@aws-sdk/client-bedrock-runtime');
      
      if (!this.originalAWS) {
        this.originalAWS = { ...AWS };
      }

      // Override BedrockRuntimeClient
      const interceptor = new AWSBedrockInterceptor(corporateClient);
      AWS.BedrockRuntimeClient = class extends AWS.BedrockRuntimeClient {
        constructor(config: any) {
          super(config);
          console.warn('Direct AWS Bedrock client detected. Routing through corporate proxy instead.');
        }

        async send(command: any): Promise<any> {
          return interceptor.handleCommand(command);
        }
      };

      console.log('Applied corporate Bedrock proxy interceptor for AWS SDK');
    } catch (error) {
      console.warn('Could not apply AWS SDK interceptor (AWS SDK not found):', error);
    }
  }

  private async handleCommand(command: any): Promise<any> {
    const commandName = command.constructor.name;

    switch (commandName) {
      case 'InvokeModelCommand':
        return this.handleInvokeModel(command);
      case 'InvokeModelWithResponseStreamCommand':
        return this.handleInvokeModelWithResponseStream(command);
      default:
        throw new CorporateBedrockError(`Unsupported AWS Bedrock command: ${commandName}`);
    }
  }

  private async handleInvokeModel(command: any): Promise<any> {
    const { modelId, body } = command.input;
    
    let requestData;
    if (typeof body === 'string') {
      requestData = JSON.parse(body);
    } else if (body instanceof Uint8Array) {
      requestData = JSON.parse(new TextDecoder().decode(body));
    } else {
      requestData = body;
    }

    const response = await this.corporateClient.invokeModel({
      modelId,
      messages: requestData.messages || [],
      maxTokens: requestData.max_tokens,
      temperature: requestData.temperature,
      topP: requestData.top_p,
      system: requestData.system,
      stopSequences: requestData.stop_sequences
    });

    // Return in AWS SDK format
    return {
      body: new TextEncoder().encode(JSON.stringify(response)),
      contentType: 'application/json'
    };
  }

  private async handleInvokeModelWithResponseStream(command: any): Promise<any> {
    const { modelId, body } = command.input;
    
    let requestData;
    if (typeof body === 'string') {
      requestData = JSON.parse(body);
    } else if (body instanceof Uint8Array) {
      requestData = JSON.parse(new TextDecoder().decode(body));
    } else {
      requestData = body;
    }

    const streamEmitter = await this.corporateClient.invokeModelWithResponseStream({
      modelId,
      messages: requestData.messages || [],
      maxTokens: requestData.max_tokens,
      temperature: requestData.temperature,
      topP: requestData.top_p,
      system: requestData.system,
      stopSequences: requestData.stop_sequences
    });

    // Convert EventEmitter to async iterator for AWS SDK compatibility
    const asyncIterator = {
      [Symbol.asyncIterator]: async function* () {
        const chunks: any[] = [];
        let finished = false;
        let error: Error | null = null;

        streamEmitter.on('data', (chunk) => {
          chunks.push({ chunk: { bytes: new TextEncoder().encode(JSON.stringify(chunk)) } });
        });

        streamEmitter.on('end', () => {
          finished = true;
        });

        streamEmitter.on('error', (err) => {
          error = err;
          finished = true;
        });

        while (!finished || chunks.length > 0) {
          if (error) throw error;
          
          if (chunks.length > 0) {
            yield chunks.shift();
          } else {
            await new Promise(resolve => setTimeout(resolve, 10));
          }
        }
      }
    };

    return {
      body: asyncIterator,
      contentType: 'application/json'
    };
  }
}

/**
 * Configure corporate Bedrock for the application
 */
export function configureCorporateBedrock(config?: CorporateBedrockConfig): CorporateBedrockClient {
  const client = new CorporateBedrockClient(config);
  
  // Apply AWS SDK interceptor
  AWSBedrockInterceptor.applyInterceptor(client);
  
  console.log('Corporate Bedrock configuration applied');
  return client;
}

// Example usage
export async function exampleUsage(): Promise<void> {
  try {
    // Initialize corporate client
    const client = configureCorporateBedrock({
      proxyEndpoint: 'https://your-api-gateway-url.amazonaws.com/prod',
      apiKey: 'your-corporate-api-key',
      userId: 'john.doe',
      department: 'engineering'
    });

    // Example conversation
    const response = await client.invokeModel({
      modelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
      messages: [
        {
          role: 'user',
          content: 'What are the key principles of secure software development?'
        }
      ],
      maxTokens: 1000,
      temperature: 0.7
    });

    console.log('Claude Response:');
    console.log(response.content[0]?.text || 'No response');

    // Example streaming usage
    const streamEmitter = await client.invokeModelWithResponseStream({
      modelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
      messages: [
        {
          role: 'user',
          content: 'Tell me a short story about AI and humanity.'
        }
      ],
      maxTokens: 500
    });

    streamEmitter.on('data', (chunk) => {
      if (chunk.type === 'content_block_delta') {
        process.stdout.write(chunk.delta?.text || '');
      }
    });

    streamEmitter.on('end', () => {
      console.log('\nStreaming complete');
    });

    streamEmitter.on('error', (error) => {
      console.error('Streaming error:', error);
    });

    // Get usage metrics
    const metrics = await client.getUsageMetrics();
    console.log('Usage metrics:', metrics);

  } catch (error) {
    console.error('Example error:', error);
  }
}

// Export types and classes
export default CorporateBedrockClient;