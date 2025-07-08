#!/bin/bash
# deploy-bedrock-proxy.sh
# Complete deployment script for AWS Bedrock Claude access control solution

set -e

# Configuration variables
ORGANIZATION_NAME="${ORGANIZATION_NAME:-mycompany}"
ENVIRONMENT="${ENVIRONMENT:-prod}"
AWS_REGION="${AWS_REGION:-us-east-1}"
TERRAFORM_BACKEND_BUCKET="${TERRAFORM_BACKEND_BUCKET:-}"
LAMBDA_RUNTIME="python3.11"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_status "Checking dependencies..."
    
    local deps=("terraform" "aws" "python3" "pip" "node" "npm")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_error "Please install the missing dependencies and try again."
        exit 1
    fi
    
    print_success "All dependencies are installed"
}

setup_terraform_backend() {
    if [ -z "$TERRAFORM_BACKEND_BUCKET" ]; then
        print_warning "No Terraform backend bucket specified. Using local state."
        return
    fi
    
    print_status "Setting up Terraform backend..."
    
    # Create backend configuration
    cat > backend.tf << EOF
terraform {
  backend "s3" {
    bucket         = "$TERRAFORM_BACKEND_BUCKET"
    key            = "bedrock-proxy/${ENVIRONMENT}/terraform.tfstate"
    region         = "$AWS_REGION"
    encrypt        = true
    dynamodb_table = "${TERRAFORM_BACKEND_BUCKET}-lock"
  }
}
EOF
    
    print_success "Terraform backend configured"
}

package_lambda_function() {
    print_status "Packaging Lambda function..."
    
    # Create Lambda deployment package
    mkdir -p lambda-package
    
    # Copy Lambda function code
    cp lambda_proxy_function.py lambda-package/
    
    # Install Python dependencies
    cd lambda-package
    pip install boto3 requests -t .
    
    # Create deployment package
    zip -r ../bedrock-proxy-lambda.zip .
    cd ..
    
    # Clean up
    rm -rf lambda-package
    
    print_success "Lambda function packaged"
}

create_dynamodb_table() {
    print_status "Creating DynamoDB table for usage tracking..."
    
    aws dynamodb create-table \
        --table-name "${ORGANIZATION_NAME}-bedrock-usage-tracking" \
        --attribute-definitions \
            AttributeName=user_id,AttributeType=S \
            AttributeName=time_window,AttributeType=S \
        --key-schema \
            AttributeName=user_id,KeyType=HASH \
            AttributeName=time_window,KeyType=RANGE \
        --billing-mode PAY_PER_REQUEST \
        --time-to-live-specification \
            AttributeName=ttl,Enabled=true \
        --region "$AWS_REGION" \
        --no-cli-pager || print_warning "DynamoDB table may already exist"
    
    print_success "DynamoDB table created/verified"
}

deploy_infrastructure() {
    print_status "Deploying infrastructure with Terraform..."
    
    # Initialize Terraform
    terraform init
    
    # Plan deployment
    terraform plan \
        -var="aws_region=$AWS_REGION" \
        -var="environment=$ENVIRONMENT" \
        -var="organization_name=$ORGANIZATION_NAME" \
        -out=tfplan
    
    # Apply deployment
    terraform apply tfplan
    
    print_success "Infrastructure deployed"
}

deploy_lambda_function() {
    print_status "Deploying Lambda function..."
    
    # Get Lambda function name from Terraform output
    LAMBDA_FUNCTION_NAME=$(terraform output -raw lambda_function_name 2>/dev/null || echo "${ORGANIZATION_NAME}-bedrock-proxy-${ENVIRONMENT}")
    
    # Update Lambda function code
    aws lambda update-function-code \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --zip-file fileb://bedrock-proxy-lambda.zip \
        --region "$AWS_REGION" \
        --no-cli-pager
    
    print_success "Lambda function deployed"
}

setup_api_gateway() {
    print_status "Configuring API Gateway..."
    
    # Get API Gateway ID from Terraform output
    API_GATEWAY_ID=$(terraform output -raw api_gateway_id 2>/dev/null)
    
    if [ -z "$API_GATEWAY_ID" ]; then
        print_error "Could not get API Gateway ID from Terraform output"
        exit 1
    fi
    
    # Deploy API Gateway
    aws apigateway create-deployment \
        --rest-api-id "$API_GATEWAY_ID" \
        --stage-name "$ENVIRONMENT" \
        --region "$AWS_REGION" \
        --no-cli-pager
    
    print_success "API Gateway configured"
}

setup_monitoring() {
    print_status "Setting up monitoring and alerts..."
    
    # Create CloudWatch dashboard
    cat > cloudwatch-dashboard.json << EOF
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          [ "Custom/Bedrock", "TokensUsed", "Department", "engineering" ],
          [ ".", "RequestCost", ".", "." ],
          [ ".", "ResponseTime", "ModelId", "anthropic.claude-3-sonnet-20240229-v1:0" ]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "$AWS_REGION",
        "title": "Bedrock Usage Metrics"
      }
    }
  ]
}
EOF
    
    aws cloudwatch put-dashboard \
        --dashboard-name "${ORGANIZATION_NAME}-bedrock-monitoring" \
        --dashboard-body file://cloudwatch-dashboard.json \
        --region "$AWS_REGION" \
        --no-cli-pager
    
    print_success "Monitoring dashboard created"
}

create_iam_users_and_groups() {
    print_status "Creating IAM users and groups..."
    
    # Create IAM group for Bedrock users
    aws iam create-group \
        --group-name "${ORGANIZATION_NAME}-bedrock-users" \
        --no-cli-pager 2>/dev/null || print_warning "IAM group may already exist"
    
    # Attach policy to group
    BEDROCK_POLICY_ARN=$(terraform output -raw bedrock_access_policy_arn 2>/dev/null)
    
    if [ -n "$BEDROCK_POLICY_ARN" ]; then
        aws iam attach-group-policy \
            --group-name "${ORGANIZATION_NAME}-bedrock-users" \
            --policy-arn "$BEDROCK_POLICY_ARN" \
            --no-cli-pager
    fi
    
    print_success "IAM groups configured"
}

generate_client_config() {
    print_status "Generating client configuration files..."
    
    # Get outputs from Terraform
    API_GATEWAY_URL=$(terraform output -raw api_gateway_invoke_url 2>/dev/null || echo "https://your-api-gateway-url.amazonaws.com/prod")
    
    # Create Python client configuration
    cat > client-config.py << EOF
# Corporate Bedrock Client Configuration
import os

# Set environment variables for the corporate client
os.environ['BEDROCK_PROXY_ENDPOINT'] = '$API_GATEWAY_URL'
os.environ['BEDROCK_API_KEY'] = 'your-corporate-api-key-here'
os.environ['USER_ID'] = 'your.username'
os.environ['DEPARTMENT'] = 'engineering'

# Import and configure the corporate client
from corporate_bedrock_client import configure_corporate_bedrock

# This will route all Bedrock calls through your corporate proxy
client = configure_corporate_bedrock()

print("Corporate Bedrock client configured successfully!")
print(f"Proxy endpoint: {os.environ['BEDROCK_PROXY_ENDPOINT']}")
EOF

    # Create Node.js client configuration
    cat > client-config.js << EOF
// Corporate Bedrock Client Configuration
const { configureCorporateBedrock } = require('./corporate-bedrock-client');

// Configure environment variables
process.env.BEDROCK_PROXY_ENDPOINT = '$API_GATEWAY_URL';
process.env.BEDROCK_API_KEY = 'your-corporate-api-key-here';
process.env.USER_ID = 'your.username';
process.env.DEPARTMENT = 'engineering';

// This will route all Bedrock calls through your corporate proxy
const client = configureCorporateBedrock();

console.log('Corporate Bedrock client configured successfully!');
console.log('Proxy endpoint:', process.env.BEDROCK_PROXY_ENDPOINT);
EOF

    # Create .env template
    cat > .env.template << EOF
# Corporate Bedrock Configuration Template
# Copy this to .env and update with your actual values

BEDROCK_PROXY_ENDPOINT=$API_GATEWAY_URL
BEDROCK_API_KEY=your-corporate-api-key-here
USER_ID=your.username
DEPARTMENT=engineering
BEDROCK_TIMEOUT=300

# Optional: Corporate proxy settings
CORPORATE_PROXY_URL=http://your-corporate-proxy:8080

# AWS credentials (leave empty to force proxy usage)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_SESSION_TOKEN=
EOF

    print_success "Client configuration files generated"
}

setup_cost_alerting() {
    print_status "Setting up cost alerting..."
    
    # Create SNS topic for cost alerts
    SNS_TOPIC_ARN=$(aws sns create-topic \
        --name "${ORGANIZATION_NAME}-bedrock-cost-alerts" \
        --region "$AWS_REGION" \
        --query 'TopicArn' \
        --output text \
        --no-cli-pager)
    
    # Create cost budget
    cat > cost-budget.json << EOF
{
  "BudgetName": "${ORGANIZATION_NAME}-bedrock-monthly-budget",
  "BudgetLimit": {
    "Amount": "5000",
    "Unit": "USD"
  },
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST",
  "CostFilters": {
    "Service": ["Amazon Bedrock"]
  },
  "TimePeriod": {
    "Start": "$(date -d 'first day of this month' '+%Y-%m-01')",
    "End": "$(date -d 'first day of next month' '+%Y-%m-01')"
  }
}
EOF

    cat > budget-notification.json << EOF
[
  {
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80
    },
    "Subscribers": [
      {
        "SubscriptionType": "SNS",
        "Address": "$SNS_TOPIC_ARN"
      }
    ]
  }
]
EOF

    aws budgets create-budget \
        --account-id "$(aws sts get-caller-identity --query Account --output text)" \
        --budget file://cost-budget.json \
        --notifications-with-subscribers file://budget-notification.json \
        --region us-east-1 \
        --no-cli-pager 2>/dev/null || print_warning "Budget may already exist"
    
    print_success "Cost alerting configured"
}

validate_deployment() {
    print_status "Validating deployment..."
    
    # Test API Gateway health check
    API_GATEWAY_URL=$(terraform output -raw api_gateway_invoke_url 2>/dev/null)
    
    if [ -n "$API_GATEWAY_URL" ]; then
        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_GATEWAY_URL/health" || echo "000")
        
        if [ "$HTTP_STATUS" = "200" ]; then
            print_success "API Gateway health check passed"
        else
            print_warning "API Gateway health check failed (HTTP $HTTP_STATUS)"
        fi
    fi
    
    # Validate VPC endpoints
    VPC_ENDPOINT_ID=$(terraform output -raw bedrock_endpoint_id 2>/dev/null)
    
    if [ -n "$VPC_ENDPOINT_ID" ]; then
        ENDPOINT_STATE=$(aws ec2 describe-vpc-endpoints \
            --vpc-endpoint-ids "$VPC_ENDPOINT_ID" \
            --query 'VpcEndpoints[0].State' \
            --output text \
            --region "$AWS_REGION" \
            --no-cli-pager 2>/dev/null || echo "unknown")
        
        if [ "$ENDPOINT_STATE" = "available" ]; then
            print_success "VPC endpoint is available"
        else
            print_warning "VPC endpoint state: $ENDPOINT_STATE"
        fi
    fi
    
    print_success "Deployment validation completed"
}

generate_documentation() {
    print_status "Generating documentation..."
    
    cat > DEPLOYMENT_SUMMARY.md << EOF
# AWS Bedrock Claude Access Control - Deployment Summary

## Deployment Information
- Organization: $ORGANIZATION_NAME
- Environment: $ENVIRONMENT
- AWS Region: $AWS_REGION
- Deployment Date: $(date)

## Infrastructure Components

### API Gateway
- Endpoint: $(terraform output -raw api_gateway_invoke_url 2>/dev/null || echo "Check Terraform outputs")
- ID: $(terraform output -raw api_gateway_id 2>/dev/null || echo "Check Terraform outputs")

### VPC Configuration
- VPC ID: $(terraform output -raw vpc_id 2>/dev/null || echo "Check Terraform outputs")
- Bedrock VPC Endpoint: $(terraform output -raw bedrock_endpoint_id 2>/dev/null || echo "Check Terraform outputs")

### IAM Roles
- Developer Role ARN: $(terraform output -raw bedrock_developer_role_arn 2>/dev/null || echo "Check Terraform outputs")

### Monitoring
- CloudWatch Dashboard: ${ORGANIZATION_NAME}-bedrock-monitoring
- SNS Topic: ${ORGANIZATION_NAME}-bedrock-cost-alerts

## Next Steps

1. **Configure API Keys**: Generate and distribute API keys for users
2. **Set up User Authentication**: Integrate with your corporate identity provider
3. **Distribute Client SDKs**: Share the Python and Node.js client libraries
4. **Configure IDE Plugins**: Update IDE settings to use the corporate proxy
5. **Train Users**: Provide training on the new access controls

## Client Configuration

Users should set these environment variables:

\`\`\`bash
export BEDROCK_PROXY_ENDPOINT="$(terraform output -raw api_gateway_invoke_url 2>/dev/null || echo "your-api-gateway-url")"
export BEDROCK_API_KEY="your-corporate-api-key"
export USER_ID="your.username"
export DEPARTMENT="your-department"
\`\`\`

## Security Notes

- All Bedrock traffic flows through VPC endpoints
- Content filtering is applied to all requests
- Rate limiting is enforced per user
- Complete audit trail is maintained
- Cost controls are in place

## Support

For issues or questions:
- Check CloudWatch logs for the Lambda function
- Review API Gateway access logs
- Monitor cost alerts in the SNS topic
- Use the generated client configuration files

EOF

    print_success "Documentation generated: DEPLOYMENT_SUMMARY.md"
}

cleanup() {
    print_status "Cleaning up temporary files..."
    rm -f tfplan bedrock-proxy-lambda.zip cloudwatch-dashboard.json
    rm -f cost-budget.json budget-notification.json backend.tf
    print_success "Cleanup completed"
}

# Main deployment workflow
main() {
    print_status "Starting AWS Bedrock Claude Access Control deployment..."
    print_status "Organization: $ORGANIZATION_NAME"
    print_status "Environment: $ENVIRONMENT"
    print_status "Region: $AWS_REGION"
    
    check_dependencies
    setup_terraform_backend
    package_lambda_function
    create_dynamodb_table
    deploy_infrastructure
    deploy_lambda_function
    setup_api_gateway
    setup_monitoring
    create_iam_users_and_groups
    setup_cost_alerting
    generate_client_config
    validate_deployment
    generate_documentation
    cleanup
    
    print_success "Deployment completed successfully!"
    print_success "Review DEPLOYMENT_SUMMARY.md for next steps and configuration details."
}

# Script execution
if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    main "$@"
fi

# Additional utility functions

# Function to create API keys
create_api_key() {
    local user_id="$1"
    local department="$2"
    
    if [ -z "$user_id" ] || [ -z "$department" ]; then
        print_error "Usage: create_api_key <user_id> <department>"
        return 1
    fi
    
    # Generate API key (in production, use proper key management)
    API_KEY=$(openssl rand -hex 32)
    
    # Store in AWS Systems Manager Parameter Store
    aws ssm put-parameter \
        --name "/bedrock-proxy/api-keys/$user_id" \
        --value "$API_KEY" \
        --type "SecureString" \
        --description "API key for $user_id in $department" \
        --tags "Key=Department,Value=$department" "Key=Environment,Value=$ENVIRONMENT" \
        --region "$AWS_REGION" \
        --no-cli-pager
    
    print_success "API key created for $user_id: $API_KEY"
    print_warning "Store this key securely - it cannot be retrieved again"
}

# Function to revoke API key
revoke_api_key() {
    local user_id="$1"
    
    if [ -z "$user_id" ]; then
        print_error "Usage: revoke_api_key <user_id>"
        return 1
    fi
    
    aws ssm delete-parameter \
        --name "/bedrock-proxy/api-keys/$user_id" \
        --region "$AWS_REGION" \
        --no-cli-pager
    
    print_success "API key revoked for $user_id"
}

# Function to update Lambda function
update_lambda() {
    package_lambda_function
    deploy_lambda_function
    print_success "Lambda function updated"
}

# Function to get deployment status
get_status() {
    print_status "Deployment Status:"
    
    # Check Terraform state
    if terraform state list &>/dev/null; then
        print_success "Terraform state: OK"
    else
        print_error "Terraform state: Not found"
    fi
    
    # Check API Gateway
    API_GATEWAY_URL=$(terraform output -raw api_gateway_invoke_url 2>/dev/null)
    if [ -n "$API_GATEWAY_URL" ]; then
        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_GATEWAY_URL/health" || echo "000")
        if [ "$HTTP_STATUS" = "200" ]; then
            print_success "API Gateway: Healthy"
        else
            print_warning "API Gateway: Unhealthy (HTTP $HTTP_STATUS)"
        fi
    else
        print_error "API Gateway: Not configured"
    fi
}