# bedrock_proxy_client.py
"""
Corporate Bedrock Client SDK
Ensures all Claude API calls go through corporate proxy infrastructure
"""

import json
import requests
import boto3
import os
import logging
from typing import Dict, Any, Optional, List, Iterator
from datetime import datetime
import time

logger = logging.getLogger(__name__)

class CorporateBedrockClient:
    """
    Corporate wrapper for AWS Bedrock that routes all requests through
    the company's controlled API Gateway proxy
    """
    
    def __init__(
        self,
        proxy_endpoint: str = None,
        api_key: str = None,
        user_id: str = None,
        department: str = None,
        timeout: int = 300
    ):
        """
        Initialize the corporate Bedrock client
        
        Args:
            proxy_endpoint: Corporate API Gateway endpoint URL
            api_key: Corporate API key for authentication
            user_id: User identifier for tracking and access control
            department: Department for cost allocation
            timeout: Request timeout in seconds
        """
        # Get configuration from environment variables if not provided
        self.proxy_endpoint = proxy_endpoint or os.environ.get('BEDROCK_PROXY_ENDPOINT')
        self.api_key = api_key or os.environ.get('BEDROCK_API_KEY')
        self.user_id = user_id or os.environ.get('USER_ID', 'unknown')
        self.department = department or os.environ.get('DEPARTMENT', 'engineering')
        self.timeout = timeout
        
        if not self.proxy_endpoint:
            raise ValueError("BEDROCK_PROXY_ENDPOINT must be provided or set as environment variable")
        
        if not self.api_key:
            raise ValueError("BEDROCK_API_KEY must be provided or set as environment variable")
        
        # Configure session with corporate proxy settings
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key,
            'X-User-ID': self.user_id,
            'X-Department': self.department,
            'User-Agent': f'CorporateBedrockClient/1.0 ({self.user_id})'
        })
        
        # Configure corporate proxy if set
        proxy_url = os.environ.get('CORPORATE_PROXY_URL')
        if proxy_url:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
        
        logger.info(f"Initialized Corporate Bedrock Client for user {self.user_id}")

    def invoke_model(
        self,
        model_id: str,
        messages: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        top_p: float = 0.9,
        system: str = None,
        stop_sequences: List[str] = None
    ) -> Dict[str, Any]:
        """
        Invoke a Claude model through the corporate proxy
        
        Args:
            model_id: Claude model identifier (e.g., 'anthropic.claude-3-sonnet-20240229-v1:0')
            messages: List of message objects with 'role' and 'content'
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0 to 1.0)
            top_p: Top-p sampling parameter
            system: System prompt
            stop_sequences: List of stop sequences
            
        Returns:
            Response from Claude model
        """
        # Validate model ID
        if not model_id.startswith('anthropic.claude'):
            raise ValueError(f"Unsupported model ID: {model_id}. Only Claude models are allowed.")
        
        # Construct request payload
        payload = {
            'modelId': model_id,
            'messages': messages,
            'inferenceConfig': {
                'maxTokens': max_tokens,
                'temperature': temperature,
                'topP': top_p
            }
        }
        
        if system:
            payload['system'] = system
            
        if stop_sequences:
            payload['inferenceConfig']['stopSequences'] = stop_sequences
        
        # Make request through corporate proxy
        return self._make_request('POST', f'/model/{model_id}/invoke', payload)

    def invoke_model_with_response_stream(
        self,
        model_id: str,
        messages: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        top_p: float = 0.9,
        system: str = None,
        stop_sequences: List[str] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Invoke a Claude model with streaming response through the corporate proxy
        
        Args:
            Same as invoke_model
            
        Yields:
            Streaming response chunks from Claude model
        """
        # Validate model ID
        if not model_id.startswith('anthropic.claude'):
            raise ValueError(f"Unsupported model ID: {model_id}. Only Claude models are allowed.")
        
        # Construct request payload
        payload = {
            'modelId': model_id,
            'messages': messages,
            'inferenceConfig': {
                'maxTokens': max_tokens,
                'temperature': temperature,
                'topP': top_p
            }
        }
        
        if system:
            payload['system'] = system
            
        if stop_sequences:
            payload['inferenceConfig']['stopSequences'] = stop_sequences
        
        # Make streaming request through corporate proxy
        url = f"{self.proxy_endpoint}/model/{model_id}/invoke-with-response-stream"
        
        try:
            with self.session.post(
                url,
                json=payload,
                timeout=self.timeout,
                stream=True
            ) as response:
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line:
                        try:
                            chunk = json.loads(line.decode('utf-8'))
                            yield chunk
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse streaming response line: {line}")
                            continue
                            
        except requests.exceptions.RequestException as e:
            logger.error(f"Streaming request failed: {str(e)}")
            raise CorporateBedrockError(f"Request failed: {str(e)}")

    def get_usage_metrics(self, start_date: str = None, end_date: str = None) -> Dict[str, Any]:
        """
        Get usage metrics for the current user
        
        Args:
            start_date: Start date in ISO format (optional)
            end_date: End date in ISO format (optional)
            
        Returns:
            Usage metrics and cost information
        """
        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
            
        return self._make_request('GET', '/usage/metrics', params=params)

    def _make_request(
        self,
        method: str,
        endpoint: str,
        payload: Dict[str, Any] = None,
        params: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request through corporate proxy"""
        url = f"{self.proxy_endpoint}{endpoint}"
        
        try:
            start_time = time.time()
            
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            elif method == 'POST':
                response = self.session.post(url, json=payload, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response_time = time.time() - start_time
            
            # Log request for audit trail
            logger.info(f"Corporate Bedrock request: {method} {endpoint} - {response.status_code} - {response_time:.2f}s")
            
            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded. Please wait before making more requests.")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            raise CorporateBedrockError(f"Request timeout after {self.timeout} seconds")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    raise CorporateBedrockError(f"Request failed: {error_details.get('error', {}).get('message', str(e))}")
                except json.JSONDecodeError:
                    raise CorporateBedrockError(f"Request failed: {str(e)}")
            else:
                raise CorporateBedrockError(f"Request failed: {str(e)}")


class CorporateBedrockError(Exception):
    """Custom exception for Corporate Bedrock Client errors"""
    pass


class RateLimitError(CorporateBedrockError):
    """Exception raised when rate limit is exceeded"""
    pass


# Monkey patch to override AWS SDK
class BedrockRuntimeMonkeyPatch:
    """
    Monkey patch for boto3 Bedrock runtime client to route through corporate proxy
    """
    
    @staticmethod
    def apply_patch():
        """Apply monkey patch to boto3 bedrock-runtime client"""
        import boto3
        
        original_client = boto3.client
        
        def patched_client(service_name, **kwargs):
            if service_name == 'bedrock-runtime':
                logger.warning(
                    "Direct Bedrock runtime client detected. "
                    "Routing through corporate proxy instead."
                )
                return CorporateBedrockBoto3Wrapper()
            return original_client(service_name, **kwargs)
        
        boto3.client = patched_client
        logger.info("Applied corporate Bedrock proxy monkey patch")


class CorporateBedrockBoto3Wrapper:
    """
    Wrapper that mimics boto3 bedrock-runtime client interface
    but routes through corporate proxy
    """
    
    def __init__(self):
        self.corporate_client = CorporateBedrockClient()
    
    def invoke_model(self, modelId: str, body: str, **kwargs) -> Dict[str, Any]:
        """Mimic boto3 invoke_model interface"""
        try:
            # Parse the body (usually JSON string)
            request_data = json.loads(body) if isinstance(body, str) else body
            
            # Extract Claude API parameters
            messages = request_data.get('messages', [])
            max_tokens = request_data.get('max_tokens', 4096)
            temperature = request_data.get('temperature', 0.7)
            top_p = request_data.get('top_p', 0.9)
            system = request_data.get('system')
            stop_sequences = request_data.get('stop_sequences')
            
            # Make request through corporate client
            response = self.corporate_client.invoke_model(
                model_id=modelId,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                system=system,
                stop_sequences=stop_sequences
            )
            
            # Return in boto3 format
            return {
                'body': MockStreamingBody(json.dumps(response)),
                'contentType': 'application/json',
                'ResponseMetadata': {
                    'HTTPStatusCode': 200,
                    'HTTPHeaders': {},
                    'RetryAttempts': 0
                }
            }
            
        except Exception as e:
            logger.error(f"Boto3 wrapper error: {str(e)}")
            raise

    def invoke_model_with_response_stream(self, modelId: str, body: str, **kwargs):
        """Mimic boto3 invoke_model_with_response_stream interface"""
        try:
            # Parse the body
            request_data = json.loads(body) if isinstance(body, str) else body
            
            # Extract Claude API parameters
            messages = request_data.get('messages', [])
            max_tokens = request_data.get('max_tokens', 4096)
            temperature = request_data.get('temperature', 0.7)
            top_p = request_data.get('top_p', 0.9)
            system = request_data.get('system')
            stop_sequences = request_data.get('stop_sequences')
            
            # Get streaming response through corporate client
            stream = self.corporate_client.invoke_model_with_response_stream(
                model_id=modelId,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                system=system,
                stop_sequences=stop_sequences
            )
            
            # Return in boto3 format
            return {
                'body': MockEventStream(stream),
                'contentType': 'application/json',
                'ResponseMetadata': {
                    'HTTPStatusCode': 200,
                    'HTTPHeaders': {},
                    'RetryAttempts': 0
                }
            }
            
        except Exception as e:
            logger.error(f"Boto3 streaming wrapper error: {str(e)}")
            raise


class MockStreamingBody:
    """Mock StreamingBody to mimic boto3 response format"""
    
    def __init__(self, content: str):
        self.content = content.encode('utf-8')
        self.position = 0
    
    def read(self, amt: int = None) -> bytes:
        if amt is None:
            result = self.content[self.position:]
            self.position = len(self.content)
        else:
            result = self.content[self.position:self.position + amt]
            self.position += len(result)
        return result


class MockEventStream:
    """Mock EventStream to mimic boto3 streaming response format"""
    
    def __init__(self, stream: Iterator[Dict[str, Any]]):
        self.stream = stream
    
    def __iter__(self):
        for chunk in self.stream:
            yield {
                'chunk': {
                    'bytes': json.dumps(chunk).encode('utf-8')
                }
            }


# Configuration helper
def configure_corporate_bedrock():
    """
    Configure environment for corporate Bedrock usage
    Call this at the start of your application
    """
    # Apply monkey patch to intercept direct boto3 calls
    BedrockRuntimeMonkeyPatch.apply_patch()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Corporate Bedrock configuration applied")


# Example usage and testing
if __name__ == "__main__":
    # Example usage of the corporate client
    
    # Configure corporate proxy
    configure_corporate_bedrock()
    
    # Initialize client
    client = CorporateBedrockClient(
        proxy_endpoint="https://your-api-gateway-url.amazonaws.com/prod",
        api_key="your-corporate-api-key",
        user_id="john.doe",
        department="engineering"
    )
    
    # Example Claude conversation
    try:
        response = client.invoke_model(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[
                {
                    "role": "user",
                    "content": "What are the key principles of secure software development?"
                }
            ],
            max_tokens=1000,
            temperature=0.7
        )
        
        print("Claude Response:")
        print(response.get('content', [{}])[0].get('text', 'No response'))
        
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Test with boto3 wrapper (should automatically route through proxy)
    try:
        import boto3
        
        # This will now use the corporate proxy instead of direct AWS
        bedrock = boto3.client('bedrock-runtime')
        
        response = bedrock.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=json.dumps({
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello from boto3 wrapper!"
                    }
                ],
                "max_tokens": 100
            })
        )
        
        print("Boto3 wrapper response:")
        print(json.loads(response['body'].read()))
        
    except Exception as e:
        print(f"Boto3 wrapper error: {str(e)}")


# Environment configuration script
def create_env_config():
    """Create sample environment configuration"""
    env_config = """
# Corporate Bedrock Configuration
export BEDROCK_PROXY_ENDPOINT="https://your-api-gateway-id.execute-api.us-east-1.amazonaws.com/prod"
export BEDROCK_API_KEY="your-corporate-api-key"
export USER_ID="your.username"
export DEPARTMENT="engineering"
export CORPORATE_PROXY_URL="http://your-corporate-proxy:8080"

# Optional: Override AWS credentials to prevent direct access
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_SESSION_TOKEN=""
"""
    
    with open('.env.corporate-bedrock', 'w') as f:
        f.write(env_config)
    
    print("Created .env.corporate-bedrock configuration file")
    print("Please update the values and source this file:")
    print("source .env.corporate-bedrock")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "create-config":
        create_env_config()
    else:
        # Run example usage
        pass
            