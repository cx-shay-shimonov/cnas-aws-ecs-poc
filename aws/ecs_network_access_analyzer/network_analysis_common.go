// Package ecsnetworkaccessanalyzer provides shared utilities for network analysis operations.
// This file contains common functions used by both VPC and Scope analysis approaches.
package ecsnetworkaccessanalyzer

import (
	"context"
	"fmt"

	ecsTypes "aws-ecs-project/aws/ecs_types"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog"
)

// logNICExposureStatus logs the exposure status of a NIC in a consistent format.
func logNICExposureStatus(nicID string, isExposed bool, cnasLogger zerolog.Logger) {
	status := "not exposed"
	if isExposed {
		status = "publicly exposed"
	}
	cnasLogger.Info().Msgf("ECS Crawler: NIC %s is %s", nicID, status)
}

// findInternetGatewayForVPC finds the internet gateway for a given VPC with proper pagination.
func findInternetGatewayForVPC(ctx context.Context, ec2Client *ec2.Client, vpcID string, cnasLogger zerolog.Logger) (string, error) {
	var nextToken *string

	for {
		describeGwsInput := &ec2.DescribeInternetGatewaysInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("attachment.vpc-id"),
					Values: []string{vpcID},
				},
			},
			MaxResults: aws.Int32(maxInternetGatewaysPerCall),
			NextToken:  nextToken,
		}

		describeGwsOutput, err := ec2Client.DescribeInternetGateways(ctx, describeGwsInput)
		if err != nil {
			return "", fmt.Errorf("failed to describe internet gateways: %w", err)
		}

		// Check if we found any internet gateways in this page
		if len(describeGwsOutput.InternetGateways) > 0 {
			igwID := aws.ToString(describeGwsOutput.InternetGateways[0].InternetGatewayId)
			cnasLogger.Debug().Msgf("ECS Crawler: Found internet gateway %s for VPC %s", igwID, vpcID)

			return igwID, nil
		}

		// Check if there are more pages
		if describeGwsOutput.NextToken == nil {
			break
		}

		nextToken = describeGwsOutput.NextToken
	}

	// No internet gateway found
	cnasLogger.Debug().Msgf("ECS Crawler: No internet gateway found for VPC %s", vpcID)

	return "", nil
}

// updateContainerExposureStatus updates the PublicExposed field of containers based on NIC analysis results.
// It merges analysisResults into nicExposureMap and logs the exposure status of each NIC.
func updateContainerExposureStatus(containers []ecsTypes.ContainerData, analysisResults, nicExposureMap map[string]bool, logger zerolog.Logger) {
	// Merge analysis results into exposure map and log status
	for nicID, isExposed := range analysisResults {
		nicExposureMap[nicID] = isExposed
		logNICExposureStatus(nicID, isExposed, logger)
	}

	// Update containers based on their NIC exposure status
	for i := range containers {
		container := &containers[i]

		if container.NicID == "" {
			logger.Warn().Msgf("ECS Crawler: Container %s has no valid NIC ID", container.Name)
			continue
		}

		if isExposed, exists := nicExposureMap[container.NicID]; exists {
			container.PublicExposed = isExposed
		} else {
			logger.Warn().Msgf("ECS Crawler: NIC %s for container %s not found in analysis results",
				container.NicID, container.Name)
		}
	}
}
