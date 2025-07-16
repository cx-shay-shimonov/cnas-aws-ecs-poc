#!/bin/bash

# AWS ECS/ECR Go Application Runner
# This script sets the correct AWS profile and runs the application

echo "🚀 Starting AWS ECS/ECR Go Application..."
echo "📋 Using AWS Profile: ASTProd-Developers-602005780816"
echo ""

# Set AWS profile and run the application
export AWS_PROFILE=ASTProd-Developers-602005780816
/opt/homebrew/bin/go run main.go 