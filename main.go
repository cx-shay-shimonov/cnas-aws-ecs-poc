package main

import (
	"github.com/aws/aws-sdk-go-v2/aws"

	aws2 "aws-ecs-project/aws"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"log"
	"os"
	"strconv"
	"strings"
)

// Global constant for the target role ARN
const DefaultRegion = "us-east-1" // Default region for getting all regions
const TargetRoleArn = "arn:aws:iam::822112283600:role/CnasTargetRole"
const DebugFastMode = true // Set to true for faster testing, skips region discovery

func main() {
	// Create a context
	ctx := context.TODO()

	defaultCfg, err := aws2.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
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
		regionsNames := make([]string, len(regions))
		for i, region := range regions {
			regionsNames[i] = aws.ToString(region.RegionName)
		}
	}

	fmt.Printf("🌍 Found %d regions to explore: %v\n\n", len(regionsNames), regionsNames)

	if len(regionsNames) == 0 {
		fmt.Printf("No regions found, skipping EKS discovery")
		//return nil, nil, fmt.Errorf("no regions found")
	}

	cfg, err := aws2.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
	if err != nil {
		fmt.Printf("❌ Failed to load AWS configuration for role %s: %v\n", TargetRoleArn, err)
		return
	}

	resources := aws2.EcsCrawl(regionsNames, ctx, cfg)

	// Save detailed results to CSV file after all regions are processed
	if len(resources) > 0 {
		fmt.Printf("💾 Saving %d results to containers.csv...\n", len(resources))

		// Create CSV file
		file, err := os.Create("containers.csv")
		if err != nil {
			log.Printf("❌ Failed to create CSV file: %v", err)
			return
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("❌ Failed to close CSV file: %v", err)
			} else {
				fmt.Println("✅ CSV file closed successfully")
			}
		}(file)

		// Create CSV writer
		writer := csv.NewWriter(file)
		defer writer.Flush()

		// Write CSV headers
		headers := []string{"ID", "Name", "Type", "Image", "ImageSHA", "PublicExposed", "Correlation", "ClusterName", "ClusterType", "ProviderID", "Region", "Metadata"}
		if err := writer.Write(headers); err != nil {
			log.Printf("❌ Failed to write CSV headers: %v", err)
			return
		}

		// Write each result as CSV row
		for _, result := range resources {
			// Handle metadata - convert map to key=value pairs
			metadataStr := ""
			if len(result.StoreResourceFlat.Metadata) > 0 {
				var metadataPairs []string
				for key, value := range result.StoreResourceFlat.Metadata {
					metadataPairs = append(metadataPairs, fmt.Sprintf("%s=%s", key, value))
				}
				metadataStr = strings.Join(metadataPairs, ";")
			}

			// Create CSV row
			row := []string{
				result.ID,
				result.StoreResourceFlat.Name,
				string(result.StoreResourceFlat.Type),
				result.StoreResourceFlat.Image,
				result.StoreResourceFlat.ImageSHA,
				strconv.FormatBool(result.StoreResourceFlat.PublicExposed),
				result.StoreResourceFlat.Correlation,
				result.StoreResourceFlat.ClusterName,
				string(result.StoreResourceFlat.ClusterType),
				result.StoreResourceFlat.ProviderID,
				result.StoreResourceFlat.Region,
				metadataStr,
			}

			// Write row to CSV
			if err := writer.Write(row); err != nil {
				log.Printf("❌ Failed to write CSV row: %v", err)
				continue
			}
		}

		fmt.Printf("✅ Successfully saved %d container records to containers.csv\n", len(resources))
	} else {
		fmt.Println("📝 No containers found to save to CSV")
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

	fmt.Printf("✅ Found %d AWS regions: %v\n", len(resp.Regions), resp.Regions)
	return resp.Regions, nil
}
