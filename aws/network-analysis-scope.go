package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// runScopeAnalysis performs real AWS Network Access Scope analysis following reference code pattern
// Groups containers by ENI to avoid duplicate scopes, then maps findings back to all containers on each ENI.
func runScopeAnalysis(ctx context.Context, ec2Client *ec2.Client, containers []ContainerData, cnasLogger zerolog.Logger) (map[string]bool, error) {
	results := make(map[string][]ec2types.AccessScopePath)
	nicExposureMap := make(map[string]bool)

	// Group containers by their network interfaces to avoid duplicate scopes (like reference code)
	eniToContainers := make(map[string][]ContainerData)
	for _, container := range containers {
		if container.NicID != "" {
			eniToContainers[container.NicID] = append(eniToContainers[container.NicID], container)
		}
	}

	cnasLogger.Info().Msgf("ECS Crawler: Starting real AWS Network Access Scope analysis for %d unique ENIs across %d containers", len(eniToContainers), len(containers))

	if len(eniToContainers) == 0 {
		cnasLogger.Warn().Msg("ECS Crawler: No ENI IDs found for scope analysis")
		return nicExposureMap, nil
	}

	// Define common web ports to check (like the reference code)
	ports := []string{"80", "443", "8080", "3000", "8000", "9000"}

	// Create and analyze scope for each unique ENI (exactly like reference code)
	eniCount := 0
	for eni, containersOnENI := range eniToContainers {
		eniCount++
		cnasLogger.Info().Msgf("ECS Crawler: Checking ENI %s (%d/%d) (containers: %s)",
			eni, eniCount, len(eniToContainers),
			func() string {
				var names []string
				for _, c := range containersOnENI {
					names = append(names, c.Name)
				}
				return strings.Join(names, ", ")
			}())

		findings, err := checkSpecificENIAccess(ctx, ec2Client, eni, ports, cnasLogger)
		if err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Failed to check ENI %s: %v", eni, err)
			// Continue to next ENI like reference code
			continue
		}

		// Map findings back to all containers on this ENI (like reference code)
		for _, container := range containersOnENI {
			containerKey := fmt.Sprintf("%s/%s", container.TaskARN, container.Name)
			results[containerKey] = findings
		}

		// Update exposure map for this ENI
		nicExposureMap[eni] = len(findings) > 0

		if len(findings) > 0 {
			cnasLogger.Info().Msgf("ECS Crawler: ENI %s is publicly exposed (%d findings)", eni, len(findings))
		} else {
			cnasLogger.Debug().Msgf("ECS Crawler: ENI %s is private (no findings)", eni)
		}
	}

	cnasLogger.Info().Msgf("ECS Crawler: Real AWS Network Access Scope analysis completed for %d unique ENIs", len(eniToContainers))
	return nicExposureMap, nil
}

// checkSpecificENIAccess creates a targeted scope for a specific ENI (following reference code pattern exactly)
func checkSpecificENIAccess(ctx context.Context, ec2Client *ec2.Client, eniID string, ports []string, cnasLogger zerolog.Logger) ([]ec2types.AccessScopePath, error) {
	cnasLogger.Debug().Msgf("ECS Crawler: Starting checkSpecificENIAccess for ENI %s with ports %v", eniID, ports)

	// Create match paths targeting the specific ENI (fixed API usage)
	matchPaths := []ec2types.AccessScopePathRequest{
		{
			Source: &ec2types.PathStatementRequest{
				ResourceStatement: &ec2types.ResourceStatementRequest{
					// Use ResourceTypes only for source (Internet Gateway)
					ResourceTypes: []string{
						"AWS::EC2::InternetGateway",
					},
				},
			},
			Destination: &ec2types.PathStatementRequest{
				ResourceStatement: &ec2types.ResourceStatementRequest{
					// Use Resources only for destination (specific ENI)
					Resources: []string{eniID}, // Target specific ENI
				},
				PacketHeaderStatement: &ec2types.PacketHeaderStatementRequest{
					DestinationPorts: ports,
					Protocols:        []ec2types.Protocol{ec2types.ProtocolTcp},
					SourceAddresses:  []string{"0.0.0.0/0"},
				},
			},
		},
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Created %d match paths for ENI %s", len(matchPaths), eniID)

	cnasLogger.Debug().Msgf("ECS Crawler: Creating network access scope for ENI %s with %d match paths", eniID, len(matchPaths))

	// Create scope (exactly like reference code)
	scopeInput := &ec2.CreateNetworkInsightsAccessScopeInput{
		ClientToken: aws.String(fmt.Sprintf("eni-scope-%s-%d", eniID, time.Now().Unix())),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeNetworkInsightsAccessScope,
				Tags: []ec2types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(fmt.Sprintf("Check-ENI-%s", eniID)),
					},
					{
						Key:   aws.String("TargetENI"),
						Value: aws.String(eniID),
					},
				},
			},
		},
		MatchPaths: matchPaths,
	}

	cnasLogger.Debug().Msgf("ECS Crawler: About to call CreateNetworkInsightsAccessScope for ENI %s", eniID)
	scopeResult, err := ec2Client.CreateNetworkInsightsAccessScope(ctx, scopeInput)
	cnasLogger.Debug().Msgf("ECS Crawler: CreateNetworkInsightsAccessScope call completed for ENI %s (err: %v)", eniID, err)
	if err != nil {
		cnasLogger.Error().Msgf("ECS Crawler: Failed to create scope for ENI %s: %v", eniID, err)
		return nil, fmt.Errorf("failed to create scope for ENI %s: %w", eniID, err)
	}

	scopeID := aws.ToString(scopeResult.NetworkInsightsAccessScope.NetworkInsightsAccessScopeId)

	// Ensure cleanup of scope
	defer func() {
		cnasLogger.Debug().Msgf("ECS Crawler: Cleaning up scope %s for ENI %s", scopeID, eniID)
		_, err := ec2Client.DeleteNetworkInsightsAccessScope(ctx, &ec2.DeleteNetworkInsightsAccessScopeInput{
			NetworkInsightsAccessScopeId: aws.String(scopeID),
		})
		if err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Failed to delete scope %s: %v", scopeID, err)
		}
	}()

	// Start analysis (exactly like reference code)
	analysisInput := &ec2.StartNetworkInsightsAccessScopeAnalysisInput{
		NetworkInsightsAccessScopeId: aws.String(scopeID),
		ClientToken:                  aws.String(fmt.Sprintf("analysis-%s-%d", eniID, time.Now().Unix())),
	}

	cnasLogger.Debug().Msgf("ECS Crawler: About to start analysis for scope %s", scopeID)
	analysisResult, err := ec2Client.StartNetworkInsightsAccessScopeAnalysis(ctx, analysisInput)
	cnasLogger.Debug().Msgf("ECS Crawler: StartNetworkInsightsAccessScopeAnalysis call completed (err: %v)", err)
	if err != nil {
		return nil, fmt.Errorf("failed to start analysis for ENI %s: %w", eniID, err)
	}

	analysisID := aws.ToString(analysisResult.NetworkInsightsAccessScopeAnalysis.NetworkInsightsAccessScopeAnalysisId)

	// Wait for completion (using the same pattern as reference code)
	cnasLogger.Info().Msgf("ECS Crawler: Starting to poll for analysis %s completion", analysisID)
	if err := waitForAnalysis(ctx, ec2Client, analysisID, cnasLogger); err != nil {
		cnasLogger.Error().Msgf("ECS Crawler: Analysis %s failed: %v", analysisID, err)
		return nil, err
	}
	cnasLogger.Info().Msgf("ECS Crawler: Analysis %s completed successfully", analysisID)

	// Get findings (exactly like reference code)
	cnasLogger.Info().Msgf("ECS Crawler: Retrieving findings for analysis %s", analysisID)
	findingsInput := &ec2.GetNetworkInsightsAccessScopeAnalysisFindingsInput{
		NetworkInsightsAccessScopeAnalysisId: aws.String(analysisID),
	}

	findingsResult, err := ec2Client.GetNetworkInsightsAccessScopeAnalysisFindings(ctx, findingsInput)
	if err != nil {
		cnasLogger.Error().Msgf("ECS Crawler: Failed to get findings for analysis %s: %v", analysisID, err)
		return nil, fmt.Errorf("failed to get findings for ENI %s: %w", eniID, err)
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Retrieved %d findings for ENI %s", len(findingsResult.AnalysisFindings), eniID)

	// For current AWS SDK, we use AnalysisFindings instead of NetworkAccessScopeFindings
	// The logic is: if there are any findings, the ENI has exposure paths

	// Create a simplified AccessScopePath list for compatibility
	var scopePaths []ec2types.AccessScopePath

	// If we have any findings at all, create a basic scope path entry
	if len(findingsResult.AnalysisFindings) > 0 {
		cnasLogger.Debug().Msgf("ECS Crawler: Found %d analysis findings indicating exposure for ENI %s",
			len(findingsResult.AnalysisFindings), eniID)

		// Create a basic AccessScopePath to indicate exposure was found
		scopePath := ec2types.AccessScopePath{
			Destination: &ec2types.PathStatement{
				ResourceStatement: &ec2types.ResourceStatement{
					Resources: []string{eniID}, // The ENI that was found to be exposed
				},
			},
		}
		scopePaths = append(scopePaths, scopePath)

		cnasLogger.Info().Msgf("ECS Crawler: ENI %s has internet exposure (confirmed by scope analysis)", eniID)
	} else {
		cnasLogger.Debug().Msgf("ECS Crawler: No findings for ENI %s - not exposed", eniID)
	}

	return scopePaths, nil
}

// waitForAnalysis waits for the analysis to complete (exactly like reference code)
func waitForAnalysis(ctx context.Context, ec2Client *ec2.Client, analysisID string, cnasLogger zerolog.Logger) error {
	timeout := time.After(scopeAnalysisTimeout)
	ticker := time.NewTicker(pollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("analysis timed out after %v", scopeAnalysisTimeout)
		case <-ticker.C:
			input := &ec2.DescribeNetworkInsightsAccessScopeAnalysesInput{
				NetworkInsightsAccessScopeAnalysisIds: []string{analysisID},
			}

			result, err := ec2Client.DescribeNetworkInsightsAccessScopeAnalyses(ctx, input)
			if err != nil {
				return err
			}

			if len(result.NetworkInsightsAccessScopeAnalyses) == 0 {
				return fmt.Errorf("analysis not found")
			}

			analysis := result.NetworkInsightsAccessScopeAnalyses[0]
			cnasLogger.Info().Msgf("ECS Crawler: Analysis %s status: %s", analysisID, analysis.Status)
			switch analysis.Status {
			case ec2types.AnalysisStatusSucceeded:
				cnasLogger.Info().Msgf("ECS Crawler: Analysis %s succeeded!", analysisID)
				return nil
			case ec2types.AnalysisStatusFailed:
				cnasLogger.Error().Msgf("ECS Crawler: Analysis %s failed: %s", analysisID, aws.ToString(analysis.StatusMessage))
				return fmt.Errorf("analysis failed: %s", aws.ToString(analysis.StatusMessage))
			case ec2types.AnalysisStatusRunning:
				cnasLogger.Debug().Msgf("ECS Crawler: Analysis %s still running, continuing to poll...", analysisID)
				// Continue waiting
			}
		}
	}
}
