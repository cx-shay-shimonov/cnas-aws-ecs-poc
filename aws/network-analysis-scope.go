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

// checkContainerExposureScopeReachability uses batch VPC analysis to simulate scope-like behavior
// This approach groups ENIs by VPC and processes them more efficiently than individual analysis.
func checkContainerExposureScopeReachability(ctx context.Context, ec2Client *ec2.Client, nicIDs []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	nicExposureMap := make(map[string]bool)

	// Initialize all NICs as not exposed
	for _, nicID := range nicIDs {
		nicExposureMap[nicID] = false
	}

	if len(nicIDs) == 0 {
		return nicExposureMap, nil
	}

	cnasLogger.Info().Msgf("ECS Crawler: Using scope-like batch analysis for %d ENIs", len(nicIDs))

	// Get VPC information for all ENIs to group them efficiently
	vpcToENIs, err := groupENIsByVPC(ctx, ec2Client, nicIDs, cnasLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to group ENIs by VPC: %w", err)
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Grouped %d ENIs across %d VPCs", len(nicIDs), len(vpcToENIs))

	// Process each VPC's ENIs in batch
	type vpcResult struct {
		vpcID      string
		eniResults map[string]bool
		err        error
	}
	resultChan := make(chan vpcResult, len(vpcToENIs))

	// Start workers for each VPC
	for vpcID, enis := range vpcToENIs {
		go func(vpcId string, vpcEnisIds []string) {
			vpcENIResults, err := analyzeVPCENIsBatch(ctx, ec2Client, vpcId, vpcEnisIds, cnasLogger)
			resultChan <- vpcResult{vpcId, vpcENIResults, err}
		}(vpcID, enis)
	}

	// Collect results from all VPCs
	for i := 0; i < len(vpcToENIs); i++ {
		result := <-resultChan
		if result.err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Error analyzing VPC %s: %v", result.vpcID, result.err)
			continue
		}

		// Merge VPC results into main map
		for eniID, isExposed := range result.eniResults {
			nicExposureMap[eniID] = isExposed
		}
	}

	cnasLogger.Info().Msgf("ECS Crawler: Scope-like analysis completed for %d ENIs", len(nicIDs))
	return nicExposureMap, nil
}

// groupENIsByVPC groups ENIs by their VPC for efficient batch processing.
func groupENIsByVPC(ctx context.Context, ec2Client *ec2.Client, nicIDs []string, cnasLogger zerolog.Logger) (map[string][]string, error) {
	vpcToENIs := make(map[string][]string)

	// Process ENIs in batches to handle pagination
	for i := 0; i < len(nicIDs); i += maxENIsPerCall {
		end := i + maxENIsPerCall
		if end > len(nicIDs) {
			end = len(nicIDs)
		}

		batch := nicIDs[i:end]
		cnasLogger.Debug().Msgf("ECS Crawler: Describing batch of %d ENIs (batch %d/%d)",
			len(batch), (i/maxENIsPerCall)+1, (len(nicIDs)+maxENIsPerCall-1)/maxENIsPerCall)

		describeInput := &ec2.DescribeNetworkInterfacesInput{
			NetworkInterfaceIds: batch,
		}

		describeOutput, err := ec2Client.DescribeNetworkInterfaces(ctx, describeInput)
		if err != nil {
			return nil, fmt.Errorf("failed to describe network interfaces batch %d: %w", (i/maxENIsPerCall)+1, err)
		}

		// Process this batch's results
		for _, eni := range describeOutput.NetworkInterfaces {
			eniID := aws.ToString(eni.NetworkInterfaceId)
			vpcID := aws.ToString(eni.VpcId)
			vpcToENIs[vpcID] = append(vpcToENIs[vpcID], eniID)
		}
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Grouped %d ENIs across %d VPCs", len(nicIDs), len(vpcToENIs))
	return vpcToENIs, nil
}

// analyzeVPCENIsBatch efficiently analyzes all ENIs in a VPC for public exposure.
func analyzeVPCENIsBatch(ctx context.Context, ec2Client *ec2.Client, vpcID string, eniIDs []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	eniResults := make(map[string]bool)

	// Initialize all ENIs as not exposed
	for _, eniID := range eniIDs {
		eniResults[eniID] = false
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Analyzing %d ENIs in VPC %s", len(eniIDs), vpcID)

	// Check if VPC has internet gateway (prerequisite for public access) with pagination
	igwID, err := findInternetGatewayForVPC(ctx, ec2Client, vpcID, cnasLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to find internet gateway for VPC %s: %w", vpcID, err)
	}

	if igwID == "" {
		cnasLogger.Debug().Msgf("ECS Crawler: VPC %s has no internet gateway - all ENIs are private", vpcID)
		return eniResults, nil // No internet gateway = all ENIs are private
	}

	cnasLogger.Debug().Msgf("ECS Crawler: VPC %s has internet gateway %s - checking ENI reachability", vpcID, igwID)

	// For efficiency in scope approach, we can batch analyze a few ENIs at once
	// Use smaller batches to avoid API limits while still being more efficient than individual calls
	for i := 0; i < len(eniIDs); i += eniAnalysisBatchSize {
		end := i + eniAnalysisBatchSize
		if end > len(eniIDs) {
			end = len(eniIDs)
		}

		batch := eniIDs[i:end]
		batchResults, err := analyzeENIBatch(ctx, ec2Client, igwID, batch, cnasLogger)
		if err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Error analyzing ENI batch in VPC %s: %v", vpcID, err)
			continue
		}

		// Merge batch results
		for eniID, isExposed := range batchResults {
			eniResults[eniID] = isExposed
		}
	}

	return eniResults, nil
}

// analyzeENIBatch analyzes a batch of ENIs using optimized batch polling.
func analyzeENIBatch(ctx context.Context, ec2Client *ec2.Client, igwID string, eniIDs []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	results := make(map[string]bool)

	// Initialize all as not exposed
	for _, eniID := range eniIDs {
		results[eniID] = false
	}

	if len(eniIDs) == 0 {
		return results, nil
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Starting batch analysis for %d ENIs", len(eniIDs))

	// Step 1: Create all network insights paths concurrently
	type pathResult struct {
		eniID  string
		pathID string
		err    error
	}
	pathChan := make(chan pathResult, len(eniIDs))

	for _, eniID := range eniIDs {
		go func(eni string) {
			pathInput := &ec2.CreateNetworkInsightsPathInput{
				Source:      aws.String(igwID),
				Destination: aws.String(eni),
				Protocol:    ec2types.ProtocolTcp,
			}
			pathOutput, err := ec2Client.CreateNetworkInsightsPath(ctx, pathInput)
			if err != nil {
				pathChan <- pathResult{eni, "", err}
				return
			}
			pathID := aws.ToString(pathOutput.NetworkInsightsPath.NetworkInsightsPathId)
			pathChan <- pathResult{eni, pathID, nil}
		}(eniID)
	}

	// Collect path creation results
	eniToPath := make(map[string]string)
	var pathIDs []string

	for i := 0; i < len(eniIDs); i++ {
		result := <-pathChan
		if result.err != nil {
			cnasLogger.Debug().Msgf("ECS Crawler: Failed to create path for ENI %s: %v", result.eniID, result.err)
			continue
		}
		eniToPath[result.eniID] = result.pathID
		pathIDs = append(pathIDs, result.pathID)
	}

	if len(pathIDs) == 0 {
		cnasLogger.Warn().Msg("ECS Crawler: No paths created successfully for batch")
		return results, nil
	}

	// Ensure cleanup of all paths
	defer func() {
		for _, pathID := range pathIDs {
			_, err := ec2Client.DeleteNetworkInsightsPath(ctx, &ec2.DeleteNetworkInsightsPathInput{
				NetworkInsightsPathId: aws.String(pathID),
			})
			if err != nil {
				cnasLogger.Debug().Msgf("ECS Crawler: Failed to delete path %s: %v", pathID, err)
			}
		}
	}()

	// Step 2: Start all analyses concurrently
	type analysisResult struct {
		pathID     string
		analysisID string
		err        error
	}
	analysisChan := make(chan analysisResult, len(pathIDs))

	for _, pathID := range pathIDs {
		go func(pID string) {
			analysisInput := &ec2.StartNetworkInsightsAnalysisInput{
				NetworkInsightsPathId: aws.String(pID),
			}
			analysisOutput, err := ec2Client.StartNetworkInsightsAnalysis(ctx, analysisInput)
			if err != nil {
				analysisChan <- analysisResult{pID, "", err}
				return
			}
			analysisID := aws.ToString(analysisOutput.NetworkInsightsAnalysis.NetworkInsightsAnalysisId)
			analysisChan <- analysisResult{pID, analysisID, nil}
		}(pathID)
	}

	// Collect analysis start results
	pathToAnalysis := make(map[string]string)
	var analysisIDs []string

	for i := 0; i < len(pathIDs); i++ {
		result := <-analysisChan
		if result.err != nil {
			cnasLogger.Debug().Msgf("ECS Crawler: Failed to start analysis for path %s: %v", result.pathID, result.err)
			continue
		}
		pathToAnalysis[result.pathID] = result.analysisID
		analysisIDs = append(analysisIDs, result.analysisID)
	}

	if len(analysisIDs) == 0 {
		cnasLogger.Warn().Msg("ECS Crawler: No analyses started successfully for batch")
		return results, nil
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Started %d analyses, beginning batch polling", len(analysisIDs))

	// Step 3: Poll all analyses using batched API calls (THIS IS THE KEY OPTIMIZATION!)
	batchResults, err := pollAnalysesBatch(ctx, ec2Client, analysisIDs, cnasLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to poll analyses batch: %w", err)
	}

	// Step 4: Map analysis results back to ENIs
	for eniID, pathID := range eniToPath {
		if analysisID, exists := pathToAnalysis[pathID]; exists {
			if isExposed, found := batchResults[analysisID]; found {
				results[eniID] = isExposed
				cnasLogger.Debug().Msgf("ECS Crawler: ENI %s analysis result: %t", eniID, isExposed)
			}
		}
	}

	cnasLogger.Info().Msgf("ECS Crawler: Batch analysis completed for %d ENIs", len(eniIDs))
	return results, nil
}

// pollAnalysesBatch polls multiple analyses using batched API calls for optimal performance.
func pollAnalysesBatch(ctx context.Context, ec2Client *ec2.Client, analysisIDs []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	results := make(map[string]bool)

	// Initialize all as not exposed
	for _, analysisID := range analysisIDs {
		results[analysisID] = false
	}

	if len(analysisIDs) == 0 {
		return results, nil
	}

	cnasLogger.Debug().Msgf("ECS Crawler: Starting batch polling for %d analyses", len(analysisIDs))

	// Track which analyses are still running
	pendingAnalyses := make(map[string]bool)
	for _, id := range analysisIDs {
		pendingAnalyses[id] = true
	}

	// Poll with timeout
	timeout := time.Now().Add(scopeAnalysisTimeout)
	pollCount := 0

	for time.Now().Before(timeout) && len(pendingAnalyses) > 0 {
		pollCount++

		// Create batches of analysis IDs to query (up to 200 per call)
		var currentBatch []string
		for analysisID := range pendingAnalyses {
			currentBatch = append(currentBatch, analysisID)
			if len(currentBatch) >= maxAnalysisIdsPerCall {
				break
			}
		}

		if len(currentBatch) == 0 {
			break
		}

		cnasLogger.Debug().Msgf("ECS Crawler: Poll #%d - checking %d analyses in batch", pollCount, len(currentBatch))

		// Batch API call - THIS IS THE KEY OPTIMIZATION!
		describeInput := &ec2.DescribeNetworkInsightsAnalysesInput{
			NetworkInsightsAnalysisIds: currentBatch,
		}

		describeOutput, err := ec2Client.DescribeNetworkInsightsAnalyses(ctx, describeInput)
		if err != nil {
			cnasLogger.Debug().Msgf("ECS Crawler: Batch polling error: %v", err)
			time.Sleep(pollingInterval)

			continue
		}

		// Process results from this batch
		completedCount := 0
		for _, analysis := range describeOutput.NetworkInsightsAnalyses {
			analysisID := aws.ToString(analysis.NetworkInsightsAnalysisId)

			switch analysis.Status {
			case ec2types.AnalysisStatusSucceeded:
				// Analysis completed successfully
				isExposed := false
				if analysis.NetworkPathFound != nil {
					isExposed = aws.ToBool(analysis.NetworkPathFound)
				}
				results[analysisID] = isExposed
				delete(pendingAnalyses, analysisID)
				completedCount++
				cnasLogger.Debug().Msgf("ECS Crawler: Analysis %s completed: exposed=%t", analysisID, isExposed)

			case ec2types.AnalysisStatusFailed:
				// Analysis failed - keep as false (not exposed)
				delete(pendingAnalyses, analysisID)
				completedCount++
				cnasLogger.Debug().Msgf("ECS Crawler: Analysis %s failed, treating as not exposed", analysisID)

			case ec2types.AnalysisStatusRunning:
				// Still running, keep in pending list
				cnasLogger.Debug().Msgf("ECS Crawler: Analysis %s still running", analysisID)
			}
		}

		if completedCount > 0 {
			cnasLogger.Debug().Msgf("ECS Crawler: Poll #%d completed %d analyses, %d still pending",
				pollCount, completedCount, len(pendingAnalyses))
		}

		// If we still have pending analyses, wait before next poll
		if len(pendingAnalyses) > 0 {
			time.Sleep(pollingInterval)
		}
	}

	// Handle any analyses that timed out
	if len(pendingAnalyses) > 0 {
		cnasLogger.Warn().Msgf("ECS Crawler: %d analyses timed out after %v", len(pendingAnalyses), scopeAnalysisTimeout)
		// Keep them as false (not exposed) - already initialized
	}

	cnasLogger.Info().Msgf("ECS Crawler: Batch polling completed in %d polls for %d analyses", pollCount, len(analysisIDs))
	return results, nil
}

// runScopeAnalysis performs scope approach analysis on a list of NIC IDs
func runScopeAnalysis(ctx context.Context, ec2Client *ec2.Client, nicsToAnalyze []string, cnasLogger zerolog.Logger) (map[string]bool, error) {
	// Use scope-based analysis (analyze all NICs at once)
	cnasLogger.Info().Msgf("ECS Crawler: Using scope-based analysis for %d NICs", len(nicsToAnalyze))

	scopeResults, err := checkContainerExposureScopeReachability(ctx, ec2Client, nicsToAnalyze, cnasLogger)
	if err != nil {
		return nil, fmt.Errorf("scope analysis failed: %w", err)
	}

	return scopeResults, nil
}
