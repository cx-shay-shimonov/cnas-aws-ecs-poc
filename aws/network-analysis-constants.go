package aws

import "time"

// NetworkAnalysisApproach represents the type of network analysis to perform.
type NetworkAnalysisApproach string

// Network analysis approach constants.
const (
	ApproachVPC   NetworkAnalysisApproach = "vpc"   // Optimized VPC Reachability Analyzer with batch processing
	ApproachScope NetworkAnalysisApproach = "scope" // Account-wide Network Access Scope
)

// Configure the network analysis approach at compile time.
const networkAnalysisApproach = ApproachScope

// API polling and timeout configurations.
const pollingInterval = 5 * time.Second
const vpcAnalysisTimeout = 2 * time.Minute
const scopeAnalysisTimeout = 10 * time.Minute // Real scope analysis takes longer

// AWS API batch size and pagination limits.
const maxENIsPerCall = 200             // AWS DescribeNetworkInterfaces limit
const maxInternetGatewaysPerCall = 200 // AWS DescribeInternetGateways limit
const maxAnalysisIdsPerCall = 200      // AWS DescribeNetworkInsightsAnalyses limit

// Batch processing configurations.
const eniAnalysisBatchSize = 3 // ENIs processed concurrently within VPC scope analysis
