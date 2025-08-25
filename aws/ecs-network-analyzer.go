package aws

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// RunAnalysis performs network analysis on containers and updates their PublicExposed status.
func RunAnalysis(ctx context.Context, awsConfig aws.Config, containers []ContainerData, cnasLogger zerolog.Logger) error {
	if len(containers) == 0 {
		return nil
	}

	// Create EC2 client for network analysis
	ec2Client := ec2.NewFromConfig(awsConfig)
	cnasLogger.Debug().Msgf("ECS Crawler: Created EC2 client for network analysis in region %s", awsConfig.Region)

	// Create a unique map of NICs to analyze (deduplication)
	nicExposureMap := make(map[string]bool)

	for _, container := range containers {
		if container.NicID != "" {
			nicExposureMap[container.NicID] = false // Initialize as not exposed
		}
	}

	cnasLogger.Info().Msgf("ECS Crawler: Analyzing %d unique NICs for %d containers using %s approach",
		len(nicExposureMap), len(containers), networkAnalysisApproach)

	// Create a slice of NICs to analyze
	nicsToAnalyze := make([]string, 0, len(nicExposureMap))
	for nicID := range nicExposureMap {
		nicsToAnalyze = append(nicsToAnalyze, nicID)
	}

	// Choose analysis approach based on compile-time configuration and dispatch
	var analysisResults map[string]bool
	var err error

	if networkAnalysisApproach == ApproachScope {
		analysisResults, err = runScopeAnalysis(ctx, ec2Client, nicsToAnalyze, cnasLogger)
	} else {
		analysisResults, err = runVPCAnalysis(ctx, ec2Client, nicsToAnalyze, cnasLogger)
	}

	if err != nil {
		return fmt.Errorf("%s analysis failed: %w", networkAnalysisApproach, err)
	}

	updateContainerExposureStatus(containers, analysisResults, nicExposureMap, cnasLogger)

	return nil
}
