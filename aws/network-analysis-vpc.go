package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// checkContainerExposureVPCReachability uses VPC Reachability Analyzer to check exposure.
func checkContainerExposureVPCReachability(ctx context.Context, ec2Client *ec2.Client, nicID string, cnasLogger zerolog.Logger) (bool, error) {
	// Get the VPC for this network interface
	describeNicsInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{nicID},
	}
	describeNicsOutput, err := ec2Client.DescribeNetworkInterfaces(ctx, describeNicsInput)
	if err != nil {
		return false, fmt.Errorf("failed to describe network interface: %w", err)
	}
	if len(describeNicsOutput.NetworkInterfaces) == 0 {
		return false, fmt.Errorf("network interface not found")
	}
	vpcID := aws.ToString(describeNicsOutput.NetworkInterfaces[0].VpcId)

	// Find the internet gateway for the VPC with pagination
	igwID, err := findInternetGatewayForVPC(ctx, ec2Client, vpcID, cnasLogger)
	if err != nil {
		return false, fmt.Errorf("failed to find internet gateway for VPC %s: %w", vpcID, err)
	}
	if igwID == "" {
		return false, nil // No internet gateway = not publicly exposed
	}

	// Create network insights path
	createPathInput := &ec2.CreateNetworkInsightsPathInput{
		Source:      aws.String(igwID),
		Destination: aws.String(nicID),
		Protocol:    ec2types.ProtocolTcp,
	}
	createPathOutput, err := ec2Client.CreateNetworkInsightsPath(ctx, createPathInput)
	if err != nil {
		return false, fmt.Errorf("failed to create network insights path: %w", err)
	}
	pathID := aws.ToString(createPathOutput.NetworkInsightsPath.NetworkInsightsPathId)

	// Start analysis
	startAnalysisInput := &ec2.StartNetworkInsightsAnalysisInput{
		NetworkInsightsPathId: aws.String(pathID),
	}
	startAnalysisOutput, err := ec2Client.StartNetworkInsightsAnalysis(ctx, startAnalysisInput)
	if err != nil {
		// Clean up path
		_, err := ec2Client.DeleteNetworkInsightsPath(ctx, &ec2.DeleteNetworkInsightsPathInput{
			NetworkInsightsPathId: aws.String(pathID),
		})
		if err != nil {
			// Log cleanup failure but don't fail the analysis
			cnasLogger.Warn().Msgf("ECS Crawler: Failed to delete network insights path: %v", err)
		}

		return false, fmt.Errorf("failed to start network insights analysis: %w", err)
	}
	analysisID := aws.ToString(startAnalysisOutput.NetworkInsightsAnalysis.NetworkInsightsAnalysisId)

	// Poll for results with timeout
	timeout := time.Now().Add(vpcAnalysisTimeout)
	for time.Now().Before(timeout) {
		describeAnalysisInput := &ec2.DescribeNetworkInsightsAnalysesInput{
			NetworkInsightsAnalysisIds: []string{analysisID},
		}
		describeAnalysisOutput, err := ec2Client.DescribeNetworkInsightsAnalyses(ctx, describeAnalysisInput)
		if err != nil {
			continue
		}

		if len(describeAnalysisOutput.NetworkInsightsAnalyses) == 0 {
			continue
		}

		analysis := describeAnalysisOutput.NetworkInsightsAnalyses[0]
		status := analysis.Status

		if status == ec2types.AnalysisStatusSucceeded || status == ec2types.AnalysisStatusFailed {
			// Clean up
			_, err := ec2Client.DeleteNetworkInsightsPath(ctx, &ec2.DeleteNetworkInsightsPathInput{
				NetworkInsightsPathId: aws.String(pathID),
			})
			if err != nil {
				// Log cleanup failure but don't fail the analysis
			}

			if analysis.NetworkPathFound != nil {
				return aws.ToBool(analysis.NetworkPathFound), nil
			}

			return false, nil
		}
		cnasLogger.Debug().Msgf("ECS Crawler: Analysis %s still running, polling again in %v", analysisID, pollingInterval)
		time.Sleep(pollingInterval)
	}

	// Timeout - clean up
	_, err = ec2Client.DeleteNetworkInsightsPath(ctx, &ec2.DeleteNetworkInsightsPathInput{
		NetworkInsightsPathId: aws.String(pathID),
	})
	if err != nil {
		return false, err
	}

	return false, fmt.Errorf("analysis timed out")
}

// runVPCAnalysis performs VPC approach analysis on a list of NIC IDs
func runVPCAnalysis(ctx context.Context, ec2Client *ec2.Client, nicsToAnalyze []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	nicExposureMap := make(map[string]bool)

	// Use VPC-based analysis (analyze each NIC individually)
	cnasLogger.Info().Msgf("ECS Crawler: Using VPC-based analysis for %d NICs", len(nicsToAnalyze))

	// Use channel for results
	type nicResult struct {
		nicID     string
		isExposed bool
		err       error
	}
	resultChan := make(chan nicResult, len(nicsToAnalyze))

	// Start workers for each unique NIC
	for _, nicID := range nicsToAnalyze {
		go func(nic string) {
			isExposed, err := checkContainerExposureVPCReachability(ctx, ec2Client, nic, cnasLogger)
			resultChan <- nicResult{nic, isExposed, err}
		}(nicID)
	}

	// Collect results and update the NIC exposure map
	for i := 0; i < len(nicsToAnalyze); i++ {
		result := <-resultChan
		if result.err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Error analyzing NIC %s: %v", result.nicID, result.err)
			// Keep the default false value for failed analyses
			nicExposureMap[result.nicID] = false
		} else {
			nicExposureMap[result.nicID] = result.isExposed
		}
	}

	return nicExposureMap, nil
}
