# AWS ECS/ECR Go Project

This project demonstrates how to use AWS SDK v2 for Go with ECS (Elastic Container Service) and ECR (Elastic Container Registry).

## 🚀 Quick Start

```bash
# Run the application
go run main.go
```

## 📦 Installed Packages

- **ECS Client**: `github.com/aws/aws-sdk-go-v2/service/ecs`
- **ECR Client**: `github.com/aws/aws-sdk-go-v2/service/ecr`
- **AWS Config**: `github.com/aws/aws-sdk-go-v2/config`

## 🔧 AWS Configuration

To use the AWS services, you need to configure your AWS credentials and region. Here are the options:

### Option 1: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-west-2"
```

### Option 2: AWS Credentials File
Create `~/.aws/credentials`:
```ini
[default]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key
```

Create `~/.aws/config`:
```ini
[default]
region = us-west-2
output = json
```

### Option 3: AWS CLI
```bash
# Install AWS CLI first, then configure
aws configure
```

### Option 4: IAM Roles (for EC2/ECS)
If running on AWS infrastructure, you can use IAM roles attached to your EC2 instance or ECS task.

## 🔍 What the Application Does

1. **Loads AWS Configuration** - Automatically detects credentials from environment, files, or IAM roles
2. **Creates ECS Client** - Sets up client for Elastic Container Service operations
3. **Creates ECR Client** - Sets up client for Elastic Container Registry operations
4. **Lists ECS Clusters** - Demonstrates fetching ECS clusters in your account
5. **Lists ECR Repositories** - Demonstrates fetching ECR repositories in your account
6. **Writes Configuration** - Outputs setup details to `out.txt`

## 🛠️ Available Operations

### ECS Operations
- List clusters
- Describe services
- List tasks
- Create/update services

### ECR Operations
- List repositories
- Describe images
- Create repositories
- Push/pull images

## 📚 Documentation

- [ECS SDK Documentation](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ecs)
- [ECR SDK Documentation](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ecr)
- [AWS SDK v2 for Go](https://aws.github.io/aws-sdk-go-v2/docs/)

## ⚠️ Notes

- The application will show credential errors if AWS credentials are not configured
- Make sure you have appropriate IAM permissions for ECS and ECR operations
- The application uses the default AWS region from your configuration

## 🔐 Required IAM Permissions

For full functionality, your AWS credentials need these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:ListClusters",
                "ecs:DescribeServices",
                "ecs:ListTasks",
                "ecr:DescribeRepositories",
                "ecr:DescribeImages"
            ],
            "Resource": "*"
        }
    ]
}
``` 