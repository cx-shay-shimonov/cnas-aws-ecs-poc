package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Global constant for the target role ARN
const TARGET_ROLE_ARN = "arn:aws:iam::822112283600:role/CnasTargetRole"

func main() {
	// Create a context
	ctx := context.TODO()

	// Load AWS configuration using SSO profile
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion("eu-west-1"),
	)
	if err != nil {
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	fmt.Printf("AWS Region: %s\n", cfg.Region)
	fmt.Println("✅ AWS Configuration loaded with SSO Profile: ASTProd-Developers-602005780816")
	
	// Create ECS client
	ecsClient := ecs.NewFromConfig(cfg)
	fmt.Println("✅ ECS Client created successfully")

	// Create ECR client
	ecrClient := ecr.NewFromConfig(cfg)
	fmt.Println("✅ ECR Client created successfully")

	// Write configuration info to file
	writeConfigToFile("eu-west-1")

	// Example: List ECS clusters (requires AWS credentials)
	fmt.Println("\n--- ECS Operations ---")
	if err := listECSClusters(ctx, ecsClient); err != nil {
		fmt.Printf("⚠️ ECS operation failed: %v\n", err)
		fmt.Println("Note: This requires valid AWS credentials and permissions")
	}

	// Example: List ECR repositories (requires AWS credentials)
	fmt.Println("\n--- ECR Operations ---")
	if err := listECRRepositories(ctx, ecrClient); err != nil {
		fmt.Printf("⚠️ ECR operation failed: %v\n", err)
		fmt.Println("Note: This requires valid AWS credentials and permissions")
	}

	fmt.Println("\n🎉 AWS SDK v2 setup completed successfully!")
}

// loadAWSConfig configures AWS with AssumeRole using the hardcoded target ARN
func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	// Load default configuration first (for initial credentials)
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("eu-west-1"), // Set default region
	)
	if err != nil {
		return cfg, err
	}

	// Create STS client for assuming the target role
	stsClient := sts.NewFromConfig(cfg)
	
	cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, TARGET_ROLE_ARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "aws-ecs-cnas-session"      // Session name
		// o.ExternalID = "your-external-id"            // External ID (if required)
		// o.Duration = time.Hour                       // Session duration
	})

	fmt.Printf("🔐 Using AssumeRole with ARN: %s\n", TARGET_ROLE_ARN)

	return cfg, nil
}

func listECSClusters(ctx context.Context, client *ecs.Client) error {
	fmt.Println("Fetching ECS clusters...")
	
	input := &ecs.ListClustersInput{
		MaxResults: &[]int32{10}[0], // List up to 10 clusters
	}

	result, err := client.ListClusters(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	fmt.Printf("Found %d ECS clusters:\n", len(result.ClusterArns))
	for i, clusterArn := range result.ClusterArns {
		fmt.Printf("  %d. %s\n", i+1, clusterArn)
	}

	return nil
}

func listECRRepositories(ctx context.Context, client *ecr.Client) error {
	fmt.Println("Fetching ECR repositories...")
	
	input := &ecr.DescribeRepositoriesInput{
		MaxResults: &[]int32{10}[0], // List up to 10 repositories
	}

	result, err := client.DescribeRepositories(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to list ECR repositories: %w", err)
	}

	fmt.Printf("Found %d ECR repositories:\n", len(result.Repositories))
	for i, repo := range result.Repositories {
		fmt.Printf("  %d. %s (URI: %s)\n", i+1, *repo.RepositoryName, *repo.RepositoryUri)
	}

	return nil
}

func writeConfigToFile(region string) {
	file, err := os.Create("out.txt")
	if err != nil {
		log.Printf("Error creating file: %v", err)
		return
	}
	defer file.Close()

	content := fmt.Sprintf("AWS SDK v2 Configuration\n")
	content += fmt.Sprintf("========================\n")
	content += fmt.Sprintf("Region: %s\n", region)
	content += fmt.Sprintf("ECS Package: github.com/aws/aws-sdk-go-v2/service/ecs\n")
	content += fmt.Sprintf("ECR Package: github.com/aws/aws-sdk-go-v2/service/ecr\n")
	content += fmt.Sprintf("Config Package: github.com/aws/aws-sdk-go-v2/config\n")
	content += fmt.Sprintf("\nCredential Options Available:\n")
	content += fmt.Sprintf("- Environment Variables\n")
	content += fmt.Sprintf("- AWS Credentials File\n")
	content += fmt.Sprintf("- IAM Roles\n")
	content += fmt.Sprintf("- AssumeRole with ARN\n")
	content += fmt.Sprintf("- Profile-based Configuration\n")
	content += fmt.Sprintf("\nSetup completed successfully! ✅\n")

	_, err = file.WriteString(content)
	if err != nil {
		log.Printf("Error writing to file: %v", err)
		return
	}

	fmt.Println("✅ Configuration written to out.txt")
} 