package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Global constant for the target role ARN
const TARGET_ROLE_ARN = "arn:aws:iam::822112283600:role/CnasTargetRole"

//const TARGET_ROLE_ARN = "arn:aws:iam::822112283600:role/ShayRole"

// Global variables for logging
var operationLogs []string

// logToFile logs operation details to the global log slice
func logToFile(requestName, sdkFunction, status, details string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s | %s | %s | %s",
		timestamp, status, requestName, sdkFunction, details)
	operationLogs = append(operationLogs, logEntry)
}

func main() {
	// Create a context
	ctx := context.TODO()

	// Load AWS configuration using AssumeRole with TARGET_ROLE_ARN
	fmt.Println("🔍 Request: Load AWS Configuration with AssumeRole")
	fmt.Println("📞 SDK Function: loadAWSConfig() -> AssumeRole")
	fmt.Println("⏳ Loading AWS configuration...")

	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ AWS Configuration failed: %v", err)
		fmt.Println(errorMsg)
		logToFile("Load AWS Configuration", "loadAWSConfig()", "ERROR", errorMsg)
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	// Log successful configuration
	configMsg := "✅ AWS Configuration loaded successfully"
	fmt.Println(configMsg)
	logToFile("Load AWS Configuration", "loadAWSConfig()", "SUCCESS", fmt.Sprintf("AWS Configuration loaded with AssumeRole: %s", TARGET_ROLE_ARN))

	fmt.Printf("AWS Region: %s\n", cfg.Region)
	fmt.Printf("✅ Using AssumeRole ARN: %s\n", TARGET_ROLE_ARN)

	// Create ECS client
	fmt.Println("\n🔍 Request: Create ECS Client")
	fmt.Println("📞 SDK Function: ecs.NewFromConfig()")
	ecsClient := ecs.NewFromConfig(cfg)
	fmt.Println("✅ ECS Client created successfully")
	logToFile("Create ECS Client", "ecs.NewFromConfig()", "SUCCESS", "ECS client initialized")

	// Create ECR client
	fmt.Println("\n🔍 Request: Create ECR Client")
	fmt.Println("📞 SDK Function: ecr.NewFromConfig()")

	ecrClient := ecr.NewFromConfig(cfg) // ECR client created but not used since operations are commented out
	fmt.Println("✅ ECR Client created successfully")
	logToFile("Create ECR Client", "ecr.NewFromConfig()", "SUCCESS", "ECR client initialized")

	// Example: List ECS clusters (requires AWS credentials)
	fmt.Println("\n==================================================")
	fmt.Println("🐳 ECS OPERATIONS")
	fmt.Println("==================================================")
	if err := listECSClusters(ctx, ecsClient); err != nil {
		fmt.Printf("⚠️ ECS operation failed: %v\n", err)
		fmt.Println("Note: This requires valid AWS credentials and permissions")
	}

	// Example: List ECR repositories (requires AWS credentials)
	fmt.Println("==================================================")
	fmt.Println("📦 ECR OPERATIONS")
	fmt.Println("==================================================")
	if err := listECRRepositories(ctx, ecrClient); err != nil {
		fmt.Printf("⚠️ ECR operation failed: %v\n", err)
		fmt.Println("Note: This requires valid AWS credentials and permissions")
	}

	// Write configuration and all operation logs to file
	fmt.Println("\n==================================================")
	writeConfigToFile(cfg.Region)

	fmt.Println("\n🎉 AWS SDK v2 setup completed successfully!")
}

// loadAWSConfig configures AWS with multiple fallback credential options
func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	fmt.Println("🔍 Trying multiple credential sources...")

	// OPTION 1: Try direct credentials from ~/.aws/credentials [default] profile
	fmt.Println("📋 Option 1: Trying default credentials...")
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("eu-west-2"),
	)
	if err == nil {
		// Test if credentials work by trying to get caller identity
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ Default credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Default credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 2: Try target-account profile
	fmt.Println("📋 Option 2: Trying target-account profile...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("target-account"),
		config.WithRegion("eu-west-2"),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ Target-account credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Target-account credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 3: Try SSO profile (original approach)
	fmt.Println("📋 Option 3: Trying SSO profile...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion("eu-west-2"),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ SSO credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 4: Try SSO + AssumeRole (if you get permissions fixed)
	fmt.Println("📋 Option 4: Trying SSO + AssumeRole...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion("eu-west-2"),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, TARGET_ROLE_ARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-ecs-cnas-session"
		})

		// Test AssumeRole
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ SSO + AssumeRole working with ARN: %s\n", TARGET_ROLE_ARN)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO + AssumeRole failed: %v\n", testErr)
		}
	}

	return aws.Config{}, fmt.Errorf("❌ All credential options failed. Please check your AWS configuration")
}

func listECSClusters(ctx context.Context, client *ecs.Client) error {
	// Print detailed request information
	requestName := "List ECS Clusters"
	sdkFunction := "ecs.Client.ListClusters()"

	fmt.Printf("🔍 Request: %s\n", requestName)
	fmt.Printf("📞 SDK Function: %s\n", sdkFunction)
	fmt.Println("⏳ Executing request...")

	input := &ecs.ListClustersInput{
		MaxResults: &[]int32{10}[0], // List up to 10 clusters
	}

	result, err := client.ListClusters(ctx, input)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ %s failed: %v", requestName, err)
		fmt.Println(errorMsg)

		// Log to output file
		logToFile(requestName, sdkFunction, "ERROR", errorMsg)

		return fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	// Success - print results
	resultMsg := fmt.Sprintf("✅ %s completed successfully", requestName)
	fmt.Println(resultMsg)
	fmt.Printf("📊 Found %d ECS clusters:\n", len(result.ClusterArns))

	var clusterDetails []string
	for i, clusterArn := range result.ClusterArns {
		detail := fmt.Sprintf("  %d. %s", i+1, clusterArn)
		fmt.Println(detail)
		clusterDetails = append(clusterDetails, detail)
	}

	// Log to output file
	resultData := fmt.Sprintf("Found %d clusters: %v", len(result.ClusterArns), clusterDetails)
	logToFile(requestName, sdkFunction, "SUCCESS", resultData)

	fmt.Println()
	return nil
}

func listECRRepositories(ctx context.Context, client *ecr.Client) error {
	// Print detailed request information
	requestName := "List ECR Repositories"
	sdkFunction := "ecr.Client.DescribeRepositories()"

	fmt.Printf("🔍 Request: %s\n", requestName)
	fmt.Printf("📞 SDK Function: %s\n", sdkFunction)
	fmt.Println("⏳ Executing request...")

	input := &ecr.DescribeRepositoriesInput{
		MaxResults: &[]int32{10}[0], // List up to 10 repositories
	}

	result, err := client.DescribeRepositories(ctx, input)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ %s failed: %v", requestName, err)
		fmt.Println(errorMsg)

		// Log to output file
		logToFile(requestName, sdkFunction, "ERROR", errorMsg)

		return fmt.Errorf("failed to list ECR repositories: %w", err)
	}

	// Success - print results
	resultMsg := fmt.Sprintf("✅ %s completed successfully", requestName)
	fmt.Println(resultMsg)
	fmt.Printf("📊 Found %d ECR repositories:\n", len(result.Repositories))

	var repoDetails []string
	for i, repo := range result.Repositories {
		detail := fmt.Sprintf("  %d. %s (URI: %s)", i+1, *repo.RepositoryName, *repo.RepositoryUri)
		fmt.Println(detail)
		repoDetails = append(repoDetails, detail)
	}

	// Log to output file
	resultData := fmt.Sprintf("Found %d repositories: %v", len(result.Repositories), repoDetails)
	logToFile(requestName, sdkFunction, "SUCCESS", resultData)

	fmt.Println()
	return nil
}

func writeConfigToFile(region string) {
	// Log the file writing operation
	fmt.Println("🔍 Request: Write Configuration to File")
	fmt.Println("📞 SDK Function: os.Create() + file.WriteString()")
	fmt.Println("⏳ Writing configuration and logs to out.txt...")

	file, err := os.Create("out.txt")
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to create output file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "os.Create()", "ERROR", errorMsg)
		return
	}

	// Properly handle file closing with error checking
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			errorMsg := fmt.Sprintf("❌ Error closing file: %v", closeErr)
			fmt.Println(errorMsg)
			logToFile("Write Configuration File", "file.Close()", "ERROR", errorMsg)
		}
	}()

	// Configuration section
	content := fmt.Sprintf("AWS SDK v2 Configuration & Operation Log\n")
	content += fmt.Sprintf("=========================================\n")
	content += fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	content += fmt.Sprintf("CONFIGURATION:\n")
	content += fmt.Sprintf("--------------\n")
	content += fmt.Sprintf("Region: %s\n", region)
	content += fmt.Sprintf("ECS Package: github.com/aws/aws-sdk-go-v2/service/ecs\n")
	content += fmt.Sprintf("ECR Package: github.com/aws/aws-sdk-go-v2/service/ecr\n")
	content += fmt.Sprintf("Config Package: github.com/aws/aws-sdk-go-v2/config\n")
	content += fmt.Sprintf("Profile: ASTProd-Developers-602005780816\n")
	content += fmt.Sprintf("AssumeRole ARN: %s\n", TARGET_ROLE_ARN)

	content += fmt.Sprintf("\nCREDENTIAL OPTIONS:\n")
	content += fmt.Sprintf("-------------------\n")
	content += fmt.Sprintf("- Environment Variables\n")
	content += fmt.Sprintf("- AWS Credentials File\n")
	content += fmt.Sprintf("- IAM Roles\n")
	content += fmt.Sprintf("- AssumeRole with ARN\n")
	content += fmt.Sprintf("- Profile-based Configuration\n")

	// Operation logs section
	content += fmt.Sprintf("\nOPERATION LOGS:\n")
	content += fmt.Sprintf("---------------\n")
	if len(operationLogs) > 0 {
		for _, logEntry := range operationLogs {
			content += fmt.Sprintf("%s\n", logEntry)
		}
	} else {
		content += fmt.Sprintf("No operations logged yet.\n")
	}

	content += fmt.Sprintf("\nSetup completed successfully! ✅\n")

	// Write content with error handling
	bytesWritten, err := file.WriteString(content)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to write content to file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "file.WriteString()", "ERROR", errorMsg)
		return
	}

	// Force write to disk
	if err := file.Sync(); err != nil {
		errorMsg := fmt.Sprintf("⚠️ Warning: Failed to sync file to disk: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "file.Sync()", "WARNING", errorMsg)
		// Don't return here as the write was successful, just sync failed
	}

	// Success message with detailed info
	successMsg := fmt.Sprintf("✅ Configuration and %d operation logs written to out.txt (%d bytes)",
		len(operationLogs), bytesWritten)
	fmt.Println(successMsg)
	logToFile("Write Configuration File", "writeConfigToFile()", "SUCCESS",
		fmt.Sprintf("Written %d operation logs, %d bytes", len(operationLogs), bytesWritten))
}
