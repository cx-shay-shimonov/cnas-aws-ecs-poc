package main

import (
	"github.com/aws/aws-sdk-go-v2/aws"

	aws2 "aws-ecs-project/aws"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"log"
	"strings"
)

// Global constant for the target role ARN
const DefaultRegion = "us-east-1" // Default region for getting all regions
const TargetRoleArn = "arn:aws:iam::822112283600:role/CnasTargetRole"

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

	// Get all AWS regions
	regions, err := listRegions(ctx, defaultEC2Client)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to get AWS regions: %v", err)
		fmt.Println(errorMsg)

		log.Fatalf("Unable to get AWS regions: %v", err)
	}

	fmt.Printf("🌍 Found %d regions to explore: %v\n\n", len(regions), regions)

	resources := aws2.EcsCrawl(TargetRoleArn, regions, ctx)

	// Print detailed results after all regions are processed
	if len(resources) > 0 {
		fmt.Println("\n📋 Detailed FlatResourceResult (CSV Format):")
		fmt.Println("============================================")

		// Print CSV headers
		fmt.Println("ID,Name,Type,Image,ImageSHA,PublicExposed,Correlation,ClusterName,ClusterType,ProviderID,Region,Metadata")

		// Print each result as CSV row
		for _, result := range resources {
			// Handle metadata - convert map to key=value pairs
			metadataStr := ""
			if len(result.StoreResourceFlat.Metadata) > 0 {
				var metadataPairs []string
				for key, value := range result.StoreResourceFlat.Metadata {
					metadataPairs = append(metadataPairs, fmt.Sprintf("%s=%s", key, value))
				}
				metadataStr = fmt.Sprintf("\"%s\"", strings.Join(metadataPairs, ";"))
			}

			// Escape any commas in string fields by wrapping in quotes
			name := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Name)
			image := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Image)
			imageSHA := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.ImageSHA)
			correlation := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Correlation)
			clusterName := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.ClusterName)

			fmt.Printf("%s,%s,%s,%s,%s,%t,%s,%s,%s,%s,%s,%s\n",
				result.ID,
				name,
				result.StoreResourceFlat.Type,
				image,
				imageSHA,
				result.StoreResourceFlat.PublicExposed,
				correlation,
				clusterName,
				result.StoreResourceFlat.ClusterType,
				result.StoreResourceFlat.ProviderID,
				result.StoreResourceFlat.Region,
				metadataStr)
		}
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
