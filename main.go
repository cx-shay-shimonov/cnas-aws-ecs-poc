package main

import (
	"github.com/aws/aws-sdk-go-v2/aws"

	cnasAws "aws-ecs-project/aws"
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Global constant for the target role ARN
const DefaultRegion = "us-east-1" // Default region for getting all regions
const TargetRoleArn = "arn:aws:iam::822112283600:role/CnasTargetRole"
const DebugFastMode = false // Set to true for faster testing, skips region discovery

// MockLogger implements InfoLogger for simple console logging
type MockLogger struct{}

func (m *MockLogger) Info() cnasAws.MsgfLogger {
	return &MockEvent{}
}

// MockEvent implements MsgfLogger for formatted message output
type MockEvent struct{}

func (m *MockEvent) Msgf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func main() {
	// Create a context
	ctx := context.TODO()

	defaultCfg, err := cnasAws.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ AWS Configuration failed for default region %s: %v", DefaultRegion, err)
		fmt.Println(errorMsg)
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	defaultEC2Client := ec2.NewFromConfig(defaultCfg)
	fmt.Println("✅ EC2 Client created successfully for region discovery")
	var regionsNames []string
	if DebugFastMode {
		regionsNames = []string{"eu-west-2", "us-east-1", "us-east-2"}
	} else {
		// Get all AWS regions
		regions, err := listRegions(ctx, defaultEC2Client)
		if err != nil {
			errorMsg := fmt.Sprintf("❌ Failed to get AWS regions: %v", err)
			fmt.Println(errorMsg)

			log.Fatalf("Unable to get AWS regions: %v", err)
		}
		regionsNames = make([]string, 0)
		for _, region := range regions {
			regionsNames = append(regionsNames, aws.ToString(region.RegionName))
		}
		fmt.Printf("✅ Found %d AWS regions: %v\n", len(regionsNames), regionsNames)
	}

	fmt.Printf("🌍 Found %d regions to explore: %v\n\n", len(regionsNames), regionsNames)

	if len(regionsNames) == 0 {
		fmt.Printf("No regions found, skipping EKS discovery")
		//return nil, nil, fmt.Errorf("no regions found")
	}

	cfg, err := cnasAws.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
	if err != nil {
		fmt.Printf("❌ Failed to load AWS configuration for role %s: %v\n", TargetRoleArn, err)
		return
	}

	logger := &MockLogger{}
	resources := cnasAws.EcsCrawl(regionsNames, ctx, &cfg, logger)

	// Save detailed results to CSV and JSON files after all regions are processed
	if len(resources) > 0 {
		// Create channels to receive results from concurrent operations
		csvChan := make(chan bool, 1)
		jsonChan := make(chan bool, 1)

		// Run ExportCSV concurrently
		go func() {
			csvChan <- cnasAws.ExportCSV(resources)
		}()

		// Run ExportJSON concurrently
		go func() {
			jsonChan <- cnasAws.ExportJSON(resources)
		}()

		// Wait for both operations to complete and collect results
		csvSuccess := <-csvChan
		jsonSuccess := <-jsonChan

		// Report results
		if !csvSuccess {
			fmt.Println("❌ Failed to save results to CSV file")
		} else {
			fmt.Println("✅ Results saved to containers.csv successfully")
		}

		if !jsonSuccess {
			fmt.Println("❌ Failed to save results to JSON file")
		} else {
			fmt.Println("✅ Results saved to containers.json successfully")
		}
	} else {
		fmt.Println("📝 No containers found to save to CSV or JSON")
	}
}

// listRegions gets all AWS regions using EC2 client
func listRegions(ctx context.Context, ec2Client *ec2.Client) ([]types.Region, error) {
	fmt.Println("🌍 Getting all AWS regions...")

	resp, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	return resp.Regions, nil
}
