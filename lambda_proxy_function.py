import json
import boto3
import logging
import time
import re
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
bedrock_client = boto3.client('bedrock-runtime')
cloudwatch = boto3.client('cloudwatch')
dynamodb = boto3.resource('dynamodb')

# Environment variables
COST_TRACKING_TABLE = os.environ.get('COST_TRACKING_TABLE', 'bedrock-usage-tracking')
MAX_TOKENS_PER_REQUEST = int(os.environ.get('MAX_TOKENS_PER_REQUEST', '100000'))
DAILY_COST_LIMIT = float(os.environ.get('DAILY_COST_LIMIT', '1000.0'))
RATE_LIMIT_PER_USER = int(os.environ.get('RATE_LIMIT_PER_USER', '100'))  # requests per hour

class BedrockProxy:
    def __init__(self):
        self.usage_table = dynamodb.Table(COST_TRACKING_TABLE)
        self.model_costs = {
            'anthropic.claude-3-sonnet-20240229-v1:0': {
                'input_cost_per_1k': 0.003,
                'output_cost_per_1k': 0.015
            },
            'anthropic.claude-3-opus-20240229-v1:0': {
                'input_cost_per_1k': 0.015,
                'output_cost_per_1k': 0.075
            },
            'anthropic.claude-3-haiku-20240307-v1:0': {
                'input_cost_per_1k': 0.00025,
                'output_cost_per_1k': 0.00125
            }
        }

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler for Bedrock proxy requests"""
        try:
            # Extract user information
            user_info = self._extract_user_info(event)
            if not user_info:
                return self._create_error_response(401, "Unauthorized: Invalid or missing authentication")

            # Validate request
            validation_result = self._validate_request(event, user_info)
            if validation_result:
                return validation_result

            # Check rate limits
            rate_limit_result = self._check_rate_limits(user_info)
            if rate_limit_result:
                return rate_limit_result

            # Parse request body
            try:
                body = json.loads(event['body'])
            except (json.JSONDecodeError, KeyError):
                return self._create_error_response(400, "Invalid JSON in request body")

            # Validate Bedrock request parameters
            model_id = body.get('modelId')
            if not model_id or not model_id.startswith('anthropic.claude'):
                return self._create_error_response(400, "Invalid or unsupported model ID")

            # Check token limits
            max_tokens = body.get('inferenceConfig', {}).get('maxTokens', 0)
            if max_tokens > MAX_TOKENS_PER_REQUEST:
                return self._create_error_response(400, f"Token limit exceeded. Maximum allowed: {MAX_TOKENS_PER_REQUEST}")

            # Content filtering
            content_filter_result = self._content_filter(body)
            if content_filter_result:
                return content_filter_result

            # Make Bedrock API call
            start_time = time.time()
            
            try:
                if event['httpMethod'] == 'POST' and '/model/' in event['path'] and '/invoke' in event['path']:
                    response = self._invoke_bedrock_model(body, model_id)
                else:
                    return self._create_error_response(404, "Unsupported endpoint")

                end_time = time.time()
                response_time = end_time - start_time

                # Track usage and costs
                self._track_usage(user_info, model_id, body, response, response_time)

                # Log successful request
                self._log_request(user_info, model_id, True, response_time)

                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'X-Request-ID': context.aws_request_id,
                        'X-Response-Time': str(response_time)
                    },
                    'body': json.dumps(response)
                }

            except Exception as bedrock_error:
                logger.error(f"Bedrock API error: {str(bedrock_error)}")
                self._log_request(user_info, model_id, False, 0, str(bedrock_error))
                return self._create_error_response(500, f"Bedrock API error: {str(bedrock_error)}")

        except Exception as e:
            logger.error(f"Unexpected error in lambda_handler: {str(e)}")
            return self._create_error_response(500, "Internal server error")

    def _extract_user_info(self, event: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Extract user information from request"""
        try:
            # Check for JWT token in Authorization header
            auth_header = event.get('headers', {}).get('Authorization', '')
            if auth_header.startswith('Bearer '):
                # In production, verify JWT token here
                # For now, extract user from custom headers
                user_id = event.get('headers', {}).get('X-User-ID')
                user_role = event.get('headers', {}).get('X-User-Role', 'developer')
                department = event.get('headers', {}).get('X-Department', 'engineering')
                
                if user_id:
                    return {
                        'user_id': user_id,
                        'role': user_role,
                        'department': department,
                        'ip_address': event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
                    }

            # Check for API key authentication
            api_key = event.get('headers', {}).get('X-API-Key')
            if api_key:
                # Validate API key and extract user info
                # This would integrate with your existing auth system
                return self._validate_api_key(api_key)

            return None

        except Exception as e:
            logger.error(f"Error extracting user info: {str(e)}")
            return None

    def _validate_api_key(self, api_key: str) -> Optional[Dict[str, str]]:
        """Validate API key and return user information"""
        # This would integrate with your API key management system
        # For demonstration, using a simple hash check
        try:
            # In production, this would query your API key database
            valid_keys = {
                hashlib.sha256("dev-key-123".encode()).hexdigest(): {
                    'user_id': 'developer-1',
                    'role': 'developer',
                    'department': 'engineering'
                }
            }
            
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            return valid_keys.get(key_hash)
            
        except Exception as e:
            logger.error(f"API key validation error: {str(e)}")
            return None

    def _validate_request(self, event: Dict[str, Any], user_info: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Validate incoming request"""
        # Check HTTP method
        if event['httpMethod'] not in ['POST', 'OPTIONS']:
            return self._create_error_response(405, "Method not allowed")

        # Handle CORS preflight
        if event['httpMethod'] == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-User-ID'
                },
                'body': ''
            }

        # Check user role permissions
        if user_info['role'] not in ['developer', 'data-scientist', 'admin']:
            return self._create_error_response(403, "Insufficient permissions")

        return None

    def _check_rate_limits(self, user_info: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Check rate limits for user"""
        try:
            user_id = user_info['user_id']
            current_hour = datetime.now().strftime('%Y-%m-%d-%H')
            
            # Get current usage for this hour
            response = self.usage_table.get_item(
                Key={
                    'user_id': user_id,
                    'time_window': f"rate_limit_{current_hour}"
                }
            )
            
            current_requests = 0
            if 'Item' in response:
                current_requests = response['Item'].get('request_count', 0)

            if current_requests >= RATE_LIMIT_PER_USER:
                return self._create_error_response(429, f"Rate limit exceeded. Maximum {RATE_LIMIT_PER_USER} requests per hour.")

            # Update rate limit counter
            self.usage_table.put_item(
                Item={
                    'user_id': user_id,
                    'time_window': f"rate_limit_{current_hour}",
                    'request_count': current_requests + 1,
                    'ttl': int((datetime.now() + timedelta(hours=2)).timestamp())
                }
            )

            return None

        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            # Allow request to proceed if rate limit check fails
            return None

    def _content_filter(self, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Filter request content for policy violations"""
        try:
            # Extract text content from various message formats
            content_to_check = []
            
            # Check messages array
            messages = body.get('messages', [])
            for message in messages:
                if isinstance(message, dict) and 'content' in message:
                    if isinstance(message['content'], str):
                        content_to_check.append(message['content'])
                    elif isinstance(message['content'], list):
                        for content_item in message['content']:
                            if isinstance(content_item, dict) and content_item.get('type') == 'text':
                                content_to_check.append(content_item.get('text', ''))

            # Check system prompts
            system_prompt = body.get('system', '')
            if system_prompt:
                content_to_check.append(system_prompt)

            # Apply content filters
            for content in content_to_check:
                if self._contains_sensitive_data(content):
                    logger.warning("Request blocked due to sensitive data detection")
                    return self._create_error_response(400, "Request contains potentially sensitive information")

            return None

        except Exception as e:
            logger.error(f"Content filtering error: {str(e)}")
            # Allow request if filtering fails to avoid blocking legitimate requests
            return None

    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data patterns"""
        sensitive_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email (optional filter)
            r'password\s*[:=]\s*\S+',  # Password patterns
            r'api[_-]?key\s*[:=]\s*\S+',  # API key patterns
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def _invoke_bedrock_model(self, body: Dict[str, Any], model_id: str) -> Dict[str, Any]:
        """Invoke Bedrock model with request body"""
        try:
            response = bedrock_client.invoke_model(
                modelId=model_id,
                body=json.dumps(body),
                contentType='application/json'
            )
            
            response_body = json.loads(response['body'].read())
            return response_body

        except Exception as e:
            logger.error(f"Bedrock invocation error: {str(e)}")
            raise

    def _track_usage(self, user_info: Dict[str, str], model_id: str, request_body: Dict[str, Any], 
                    response: Dict[str, Any], response_time: float) -> None:
        """Track usage metrics and costs"""
        try:
            # Calculate token usage
            input_tokens = self._estimate_input_tokens(request_body)
            output_tokens = response.get('usage', {}).get('output_tokens', 0)
            
            # Calculate cost
            cost = self._calculate_cost(model_id, input_tokens, output_tokens)
            
            # Store usage data
            timestamp = datetime.now().isoformat()
            self.usage_table.put_item(
                Item={
                    'user_id': user_info['user_id'],
                    'time_window': timestamp,
                    'model_id': model_id,
                    'department': user_info['department'],
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'cost': float(cost),
                    'response_time': float(response_time),
                    'ttl': int((datetime.now() + timedelta(days=90)).timestamp())
                }
            )

            # Send CloudWatch metrics
            self._send_cloudwatch_metrics(user_info, model_id, input_tokens, output_tokens, cost, response_time)

        except Exception as e:
            logger.error(f"Usage tracking error: {str(e)}")

    def _estimate_input_tokens(self, request_body: Dict[str, Any]) -> int:
        """Estimate input tokens from request"""
        # Simple estimation - in production, use proper tokenization
        text_content = ""
        
        messages = request_body.get('messages', [])
        for message in messages:
            if isinstance(message, dict) and 'content' in message:
                if isinstance(message['content'], str):
                    text_content += message['content']
                elif isinstance(message['content'], list):
                    for content_item in message['content']:
                        if isinstance(content_item, dict) and content_item.get('type') == 'text':
                            text_content += content_item.get('text', '')

        # Rough estimation: 1 token ≈ 4 characters
        return len(text_content) // 4

    def _calculate_cost(self, model_id: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost based on token usage"""
        if model_id not in self.model_costs:
            return 0.0

        costs = self.model_costs[model_id]
        input_cost = (input_tokens / 1000) * costs['input_cost_per_1k']
        output_cost = (output_tokens / 1000) * costs['output_cost_per_1k']
        
        return input_cost + output_cost

    def _send_cloudwatch_metrics(self, user_info: Dict[str, str], model_id: str, 
                                input_tokens: int, output_tokens: int, cost: float, response_time: float) -> None:
        """Send custom metrics to CloudWatch"""
        try:
            metrics = [
                {
                    'MetricName': 'TokensUsed',
                    'Dimensions': [
                        {'Name': 'ModelId', 'Value': model_id},
                        {'Name': 'Department', 'Value': user_info['department']},
                        {'Name': 'UserId', 'Value': user_info['user_id']}
                    ],
                    'Value': input_tokens + output_tokens,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'RequestCost',
                    'Dimensions': [
                        {'Name': 'ModelId', 'Value': model_id},
                        {'Name': 'Department', 'Value': user_info['department']}
                    ],
                    'Value': cost,
                    'Unit': 'None'
                },
                {
                    'MetricName': 'ResponseTime',
                    'Dimensions': [
                        {'Name': 'ModelId', 'Value': model_id}
                    ],
                    'Value': response_time,
                    'Unit': 'Seconds'
                }
            ]

            cloudwatch.put_metric_data(
                Namespace='Custom/Bedrock',
                MetricData=metrics
            )

        except Exception as e:
            logger.error(f"CloudWatch metrics error: {str(e)}")

    def _log_request(self, user_info: Dict[str, str], model_id: str, success: bool, 
                    response_time: float, error: str = None) -> None:
        """Log request details for audit trail"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_info['user_id'],
            'department': user_info['department'],
            'model_id': model_id,
            'success': success,
            'response_time': response_time,
            'ip_address': user_info.get('ip_address', 'unknown')
        }
        
        if error:
            log_data['error'] = error

        if success:
            logger.info(f"Successful Bedrock request: {json.dumps(log_data)}")
        else:
            logger.error(f"Failed Bedrock request: {json.dumps(log_data)}")

    def _create_error_response(self, status_code: int, message: str) -> Dict[str, Any]:
        """Create standardized error response"""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': {
                    'message': message,
                    'code': status_code,
                    'timestamp': datetime.now().isoformat()
                }
            })
        }

# Lambda handler function
proxy = BedrockProxy()

def lambda_handler(event, context):
    return proxy.lambda_handler(event, context)