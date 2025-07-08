# AWS Bedrock Claude Access Control - Complete Implementation Guide

## Overview

This solution provides enterprise-grade access control for AWS Bedrock Claude models, ensuring all requests flow through your controlled infrastructure while providing comprehensive cost management, security, and compliance features.

## Architecture Summary

- **Client Layer**: Python/Node.js SDKs, IDE plugins, applications
- **API Gateway**: Authentication, rate limiting, content filtering
- **Security Layer**: VPC endpoints, IAM policies, audit logging
- **Cost Control**: Real-time monitoring, budget alerts, usage tracking

## Prerequisites

### Required Tools
- AWS CLI v2.x
- Terraform v1.5+
- Python 3.11+
- Node.js 18+
- Docker (optional, for containerized deployments)

### AWS Permissions
Your deployment user needs these permissions:
- IAM: Create/manage roles and policies
- VPC: Create/manage VPCs, subnets, endpoints
- API Gateway: Create/manage APIs
- Lambda: Create/manage functions
- DynamoDB: Create/manage tables
- CloudWatch: Create/manage alarms and dashboards
- Bedrock: Access to model management

## Quick Start Deployment

### 1. Clone and Prepare

```bash
# Clone the configuration files
git clone <your-repo> bedrock-access-control
cd bedrock-access-control

# Set environment variables
export ORGANIZATION_NAME="mycompany"
export ENVIRONMENT="prod"
export AWS_REGION="us-east-1"
export TERRAFORM_BACKEND_BUCKET="mycompany-terraform-state"
```

### 2. Deploy Infrastructure

```bash
# Make deployment script executable
chmod +x deploy-bedrock-proxy.sh

# Run full deployment
./deploy-bedrock-proxy.sh
```

### 3. Configure Client Access

```bash
# Create API keys for users
./deploy-bedrock-proxy.sh create_api_key "john.doe" "engineering"
./deploy-bedrock-proxy.sh create_api_key "jane.smith" "data-science"

# Get deployment status
./deploy-bedrock-proxy.sh get_status
```

## Detailed Configuration

### Client SDK Configuration

#### Python Applications

```python
# Install the corporate client
pip install requests boto3

# Configure environment
import os
os.environ['BEDROCK_PROXY_ENDPOINT'] = 'https://your-api-gateway.amazonaws.com/prod'
os.environ['BEDROCK_API_KEY'] = 'your-api-key'
os.environ['USER_ID'] = 'your.username'
os.environ['DEPARTMENT'] = 'engineering'

# Use the corporate client
from corporate_bedrock_client import CorporateBedrockClient, configure_corporate_bedrock

# Option 1: Direct client usage
client = CorporateBedrockClient()
response = client.invoke_model(
    model_id="anthropic.claude-3-sonnet-20240229-v1:0",
    messages=[{"role": "user", "content": "Hello!"}]
)

# Option 2: Automatic boto3 interception
configure_corporate_bedrock()  # This patches boto3 automatically
import boto3
bedrock = boto3.client('bedrock-runtime')  # Now routes through proxy
```

#### Node.js Applications

```javascript
// Install dependencies
npm install axios

// Configure and use
const { configureCorporateBedrock } = require('./corporate-bedrock-client');

process.env.BEDROCK_PROXY_ENDPOINT = 'https://your-api-gateway.amazonaws.com/prod';
process.env.BEDROCK_API_KEY = 'your-api-key';
process.env.USER_ID = 'your.username';
process.env.DEPARTMENT = 'engineering';

const client = configureCorporateBedrock();

// Use the client
const response = await client.invokeModel({
  modelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
  messages: [{ role: 'user', content: 'Hello!' }]
});
```

### IDE Plugin Configuration

#### VS Code Settings

Create `.vscode/settings.json`:

```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.terminal.activateEnvironment": true,
  "terminal.integrated.env.linux": {
    "BEDROCK_PROXY_ENDPOINT": "https://your-api-gateway.amazonaws.com/prod",
    "BEDROCK_API_KEY": "your-api-key",
    "USER_ID": "your.username",
    "DEPARTMENT": "engineering",
    "AWS_ACCESS_KEY_ID": "",
    "AWS_SECRET_ACCESS_KEY": ""
  }
}
```

#### IntelliJ/PyCharm Configuration

1. Go to Run → Edit Configurations
2. Add environment variables:
   - `BEDROCK_PROXY_ENDPOINT`: `https://your-api-gateway.amazonaws.com/prod`
   - `BEDROCK_API_KEY`: `your-api-key`
   - `USER_ID`: `your.username`
   - `DEPARTMENT`: `engineering`

### Corporate Proxy Integration

#### Network Configuration

```bash
# Set corporate proxy for all applications
export HTTP_PROXY="http://corporate-proxy:8080"
export HTTPS_PROXY="http://corporate-proxy:8080"
export CORPORATE_PROXY_URL="http://corporate-proxy:8080"

# Configure no-proxy for internal services
export NO_PROXY="localhost,127.0.0.1,*.internal.company.com"
```

#### Proxy Server Configuration (Squid Example)

```apache
# /etc/squid/squid.conf additions
acl bedrock_users src 10.0.0.0/8
acl bedrock_api dstdomain your-api-gateway.amazonaws.com
acl bedrock_content req_header Content-Type application/json

# Allow Bedrock API access for authenticated users
http_access allow bedrock_users bedrock_api bedrock_content

# Log all Bedrock requests for audit
access_log /var/log/squid/bedrock_access.log bedrock_users
```

## Security Configuration

### IAM Role Configuration

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockProxyAccess",
      "Effect": "Allow",
      "Action": [
        "execute-api:Invoke"
      ],
      "Resource": [
        "arn:aws:execute-api:*:*:*/prod/*/model/*/invoke*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:SourceVpc": "vpc-xxxxxxxx"
        }
      }
    }
  ]
}
```

### Content Filtering Rules

Customize the content filter in the Lambda function:

```python
def _contains_sensitive_data(self, content: str) -> bool:
    """Customize these patterns for your organization"""
    sensitive_patterns = [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit cards
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'employee[_-]?id\s*[:=]\s*\w+',  # Employee IDs
        r'confidential|proprietary|internal[_-]?only',  # Classification
        # Add your organization's patterns
    ]
    return any(re.search(pattern, content, re.IGNORECASE) for pattern in sensitive_patterns)
```

## Cost Management

### Budget Configuration

```json
{
  "BudgetName": "bedrock-monthly-budget",
  "BudgetLimit": {
    "Amount": "5000",
    "Unit": "USD"
  },
  "CostFilters": {
    "Service": ["Amazon Bedrock"],
    "TagKey": ["Department", "Project"]
  },
  "BudgetType": "COST",
  "TimeUnit": "MONTHLY"
}
```

### Usage Monitoring

```python
# Custom metrics tracking
def track_usage_by_department():
    """Track usage patterns by department"""
    
    # Query DynamoDB usage table
    response = dynamodb.query(
        TableName='bedrock-usage-tracking',
        IndexName='department-index',
        KeyConditionExpression='department = :dept',
        ExpressionAttributeValues={':dept': 'engineering'}
    )
    
    # Calculate costs and usage
    total_cost = sum(item['cost'] for item in response['Items'])
    total_tokens = sum(item['input_tokens'] + item['output_tokens'] 
                      for item in response['Items'])
    
    return {
        'department': 'engineering',
        'total_cost': total_cost,
        'total_tokens': total_tokens,
        'average_cost_per_request': total_cost / len(response['Items'])
    }
```

## Monitoring and Alerting

### CloudWatch Dashboard Setup

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["Custom/Bedrock", "TokensUsed", "Department", "engineering"],
          [".", "RequestCost", ".", "."],
          [".", "ResponseTime", "ModelId", "anthropic.claude-3-sonnet-20240229-v1:0"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "Bedrock Usage by Department"
      }
    }
  ]
}
```

### Alert Configuration

```python
# CloudWatch alarm for high costs
cloudwatch.put_metric_alarm(
    AlarmName='bedrock-high-cost-alert',
    ComparisonOperator='GreaterThanThreshold',
    EvaluationPeriods=1,
    MetricName='RequestCost',
    Namespace='Custom/Bedrock',
    Period=3600,  # 1 hour
    Statistic='Sum',
    Threshold=100.0,  # $100 per hour
    ActionsEnabled=True,
    AlarmActions=['arn:aws:sns:us-east-1:123456789012:bedrock-alerts'],
    AlarmDescription='Alert when Bedrock costs exceed $100/hour'
)
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check API key validity
aws ssm get-parameter --name "/bedrock-proxy/api-keys/your.username" --with-decryption

# Verify user permissions
aws iam get-user --user-name your.username
```

#### 2. Network Connectivity
```bash
# Test API Gateway connectivity
curl -H "X-API-Key: your-api-key" https://your-api-gateway.amazonaws.com/prod/health

# Check VPC endpoint status
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-xxxxxxxx
```

#### 3. Rate Limiting
```bash
# Check current rate limit status
aws dynamodb get-item \
  --table-name bedrock-usage-tracking \
  --key '{"user_id": {"S": "your.username"}, "time_window": {"S": "rate_limit_2024-01-15-14"}}'
```

### Log Analysis

```bash
# View Lambda function logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/bedrock-proxy-function" \
  --start-time $(date -d '1 hour ago' +%s)000

# View API Gateway access logs
aws logs filter-log-events \
  --log-group-name "API-Gateway-Execution-Logs_xxxxxxxxxx/prod" \
  --filter-pattern "[timestamp, requestId, ip, user, timestamp, method, resource, protocol, status, error, bytes, duration]"
```

## Migration Guide

### From Direct AWS SDK Usage

1. **Phase 1**: Install corporate client alongside existing code
2. **Phase 2**: Configure environment variables to route through proxy
3. **Phase 3**: Apply monkey patching to intercept boto3 calls
4. **Phase 4**: Remove direct AWS credentials from applications

### Example Migration

```python
# Before (direct AWS SDK)
import boto3
bedrock = boto3.client('bedrock-runtime')
response = bedrock.invoke_model(...)

# After (corporate proxy)
from corporate_bedrock_client import configure_corporate_bedrock
configure_corporate_bedrock()  # Patches boto3 automatically

import boto3  # Same code, now routes through proxy
bedrock = boto3.client('bedrock-runtime')
response = bedrock.invoke_model(...)  # Automatically secured
```

## Best Practices

### Security
- Rotate API keys regularly (every 90 days)
- Use IAM roles instead of long-term credentials
- Enable CloudTrail for all API Gateway calls
- Implement least-privilege access policies
- Regular security reviews of content filters

### Cost Optimization
- Set department-specific budgets
- Monitor token usage patterns
- Implement automatic scaling for rate limits
- Use appropriate Claude model for each use case
- Regular cost analysis and optimization

### Operations
- Automate deployment with CI/CD pipelines
- Monitor all key metrics continuously
- Implement automated incident response
- Regular backup of configuration and logs
- Document all customizations and procedures

## Support and Maintenance

### Regular Tasks
- **Daily**: Monitor cost and usage dashboards
- **Weekly**: Review security logs and alerts
- **Monthly**: Analyze usage patterns and optimize
- **Quarterly**: Update IAM policies and rotate credentials

### Emergency Procedures
- **High Cost Alert**: Temporarily disable high-usage users
- **Security Incident**: Revoke all API keys and audit access
- **Service Outage**: Implement emergency bypass procedures
- **Data Breach**: Follow incident response playbook

## Conclusion

This implementation provides enterprise-grade control over AWS Bedrock Claude access while maintaining developer productivity. The solution ensures all requests flow through your controlled infrastructure, providing comprehensive security, cost management, and compliance features.

For additional support or customization, refer to the generated documentation and CloudWatch logs for troubleshooting.