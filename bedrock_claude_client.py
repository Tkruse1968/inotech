import boto3
import json
import logging
from typing import Dict, List, Optional, Any
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

class ClaudeBedrockClient:
    """
    A restricted Claude client that only allows access through AWS Bedrock
    for specific accounts and enforces security policies.
    """
    
    def __init__(self, 
                 allowed_accounts: List[str],
                 allowed_regions: List[str] = None,
                 model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"):
        """
        Initialize the Claude Bedrock client with restrictions.
        
        Args:
            allowed_accounts: List of AWS account IDs allowed to use this client
            allowed_regions: List of AWS regions allowed (defaults to us-east-1, us-west-2)
            model_id: Claude model ID to use
        """
        self.allowed_accounts = set(allowed_accounts)
        self.allowed_regions = set(allowed_regions or ["us-east-1", "us-west-2"])
        self.model_id = model_id
        self.logger = logging.getLogger(__name__)
        
        # Initialize clients for each allowed region
        self.bedrock_clients = {}
        self.sts_client = boto3.client('sts')
        
        # Validate current account access
        self._validate_account_access()
        
    def _validate_account_access(self) -> None:
        """Validate that the current AWS account is allowed to use this client."""
        try:
            # Get current account ID
            identity = self.sts_client.get_caller_identity()
            current_account = identity['Account']
            current_user_arn = identity['Arn']
            
            self.logger.info(f"Current account: {current_account}, User: {current_user_arn}")
            
            if current_account not in self.allowed_accounts:
                raise PermissionError(
                    f"Account {current_account} is not authorized to use this Claude client. "
                    f"Allowed accounts: {list(self.allowed_accounts)}"
                )
                
            # Initialize Bedrock clients for allowed regions
            for region in self.allowed_regions:
                try:
                    client = boto3.client('bedrock-runtime', region_name=region)
                    # Test connectivity
                    client.list_foundation_models()
                    self.bedrock_clients[region] = client
                    self.logger.info(f"Successfully initialized Bedrock client for region: {region}")
                except ClientError as e:
                    self.logger.warning(f"Failed to initialize Bedrock client for region {region}: {e}")
                    
        except NoCredentialsError:
            raise PermissionError("No AWS credentials found. Please configure your credentials.")
        except ClientError as e:
            raise PermissionError(f"Failed to validate AWS account access: {e}")
    
    def _get_bedrock_client(self, region: str = "us-east-1"):
        """Get a Bedrock client for the specified region."""
        if region not in self.allowed_regions:
            raise ValueError(f"Region {region} is not allowed. Allowed regions: {list(self.allowed_regions)}")
            
        if region not in self.bedrock_clients:
            raise RuntimeError(f"Bedrock client not available for region {region}")
            
        return self.bedrock_clients[region]
    
    def invoke_claude(self, 
                     prompt: str, 
                     max_tokens: int = 4000,
                     temperature: float = 0.0,
                     region: str = "us-east-1",
                     system_prompt: str = None) -> Dict[str, Any]:
        """
        Invoke Claude model through Bedrock with the given prompt.
        
        Args:
            prompt: The prompt to send to Claude
            max_tokens: Maximum tokens in response
            temperature: Temperature for response generation
            region: AWS region to use
            system_prompt: Optional system prompt
            
        Returns:
            Dict containing the response from Claude
        """
        try:
            client = self._get_bedrock_client(region)
            
            # Prepare the request body
            messages = [{"role": "user", "content": prompt}]
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": messages
            }
            
            if system_prompt:
                body["system"] = system_prompt
            
            # Log the request (without sensitive data)
            self.logger.info(f"Invoking Claude model {self.model_id} in region {region}")
            
            # Invoke the model
            response = client.invoke_model(
                body=json.dumps(body),
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )
            
            # Parse response
            response_body = json.loads(response.get('body').read())
            
            # Add metadata
            response_body['metadata'] = {
                'account_id': self.sts_client.get_caller_identity()['Account'],
                'region': region,
                'timestamp': datetime.utcnow().isoformat(),
                'model_id': self.model_id
            }
            
            return response_body
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise PermissionError(f"Access denied to Claude model. Check your permissions and account restrictions.")
            elif error_code == 'ThrottlingException':
                raise RuntimeError(f"Request throttled. Please try again later.")
            else:
                raise RuntimeError(f"Bedrock API error: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error invoking Claude: {e}")
    
    def stream_claude(self, 
                     prompt: str, 
                     max_tokens: int = 4000,
                     temperature: float = 0.0,
                     region: str = "us-east-1",
                     system_prompt: str = None):
        """
        Stream response from Claude model through Bedrock.
        
        Args:
            prompt: The prompt to send to Claude
            max_tokens: Maximum tokens in response
            temperature: Temperature for response generation
            region: AWS region to use
            system_prompt: Optional system prompt
            
        Yields:
            Streaming response chunks from Claude
        """
        try:
            client = self._get_bedrock_client(region)
            
            # Prepare the request body
            messages = [{"role": "user", "content": prompt}]
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": messages
            }
            
            if system_prompt:
                body["system"] = system_prompt
            
            # Invoke the model with streaming
            response = client.invoke_model_with_response_stream(
                body=json.dumps(body),
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )
            
            # Process the streaming response
            for event in response.get('body'):
                chunk = json.loads(event['chunk']['bytes'])
                if chunk['type'] == 'content_block_delta':
                    yield chunk['delta']['text']
                elif chunk['type'] == 'message_stop':
                    break
                    
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise PermissionError(f"Access denied to Claude model. Check your permissions and account restrictions.")
            else:
                raise RuntimeError(f"Bedrock API error: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error streaming Claude: {e}")
    
    def get_account_info(self) -> Dict[str, Any]:
        """Get information about the current account and access."""
        try:
            identity = self.sts_client.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId'],
                'allowed_accounts': list(self.allowed_accounts),
                'allowed_regions': list(self.allowed_regions),
                'available_regions': list(self.bedrock_clients.keys()),
                'model_id': self.model_id
            }
        except Exception as e:
            raise RuntimeError(f"Failed to get account info: {e}")


# Example usage and configuration
def create_restricted_claude_client() -> ClaudeBedrockClient:
    """Create a Claude client with specific account restrictions."""
    
    # Define allowed AWS account IDs
    ALLOWED_ACCOUNTS = [
        "123456789012",  # Production account
        "123456789013",  # Staging account
        "123456789014"   # Development account
    ]
    
    # Define allowed regions
    ALLOWED_REGIONS = ["us-east-1", "us-west-2"]
    
    # Initialize the client
    client = ClaudeBedrockClient(
        allowed_accounts=ALLOWED_ACCOUNTS,
        allowed_regions=ALLOWED_REGIONS,
        model_id="anthropic.claude-3-5-sonnet-20241022-v2:0"
    )
    
    return client


# Usage example
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Create restricted client
        claude_client = create_restricted_claude_client()
        
        # Get account info
        account_info = claude_client.get_account_info()
        print(f"Account info: {json.dumps(account_info, indent=2)}")
        
        # Example prompt
        prompt = "Explain the benefits of using AWS Bedrock for AI applications."
        
        # Invoke Claude
        response = claude_client.invoke_claude(
            prompt=prompt,
            max_tokens=1000,
            temperature=0.1,
            system_prompt="You are a helpful AI assistant focused on AWS services."
        )
        
        print(f"Claude response: {response['content'][0]['text']}")
        
        # Example streaming
        print("\n--- Streaming Response ---")
        for chunk in claude_client.stream_claude(prompt, max_tokens=500):
            print(chunk, end='', flush=True)
            
    except PermissionError as e:
        print(f"Permission error: {e}")
    except Exception as e:
        print(f"Error: {e}")
