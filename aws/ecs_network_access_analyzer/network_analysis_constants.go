// Package ecsnetworkaccessanalyzer defines configuration constants and types for network analysis operations.
// This file contains compile-time configuration for analysis approaches, timeouts, and AWS API limits.
package ecsnetworkaccessanalyzer

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
const (
	pollingInterval      = 5 * time.Second
	vpcAnalysisTimeout   = 2 * time.Minute
	scopeAnalysisTimeout = 10 * time.Minute // Real scope analysis takes longer
)

// AWS API batch size and pagination limits.
const (
	maxENIsPerCall             = 200 // AWS DescribeNetworkInterfaces limit
	maxInternetGatewaysPerCall = 200 // AWS DescribeInternetGateways limit
	maxAnalysisIdsPerCall      = 200 // AWS DescribeNetworkInsightsAnalyses limit
)

// Batch processing configurations.
const (
	eniAnalysisBatchSize = 3 // ENIs processed concurrently within VPC scope analysis
)

// Common web service ports to analyze for public exposure.
var defaultWebPorts = []string{
	"80",   // HTTP
	"443",  // HTTPS
	"8080", // HTTP alternative
	"3000", // Development server
	"8000", // Development server
	"9000", // Development server
}
