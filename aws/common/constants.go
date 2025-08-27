// Package common provides shared constants and configuration values for the AWS crawler modules.
// This centralizes all configuration constants to avoid duplication and improve maintainability.
package common

import "time"

// AWS ECS API pagination and batch size limits.
const (
	MaxClustersPerPage       = 10  // Clusters per ListClusters call
	MaxTasksPerPage          = 100 // Tasks per ListTasks call (AWS maximum)
	TaskDescriptionBatchSize = 100 // Tasks per DescribeTasks call (AWS limit)
)

// Network analysis configuration constants.
const (
	PollingInterval      = 5 * time.Second
	VPCAnalysisTimeout   = 2 * time.Minute
	ScopeAnalysisTimeout = 10 * time.Minute // Real scope analysis takes longer
)

// AWS API batch size and pagination limits for network analysis.
const (
	MaxENIsPerCall             = 200 // AWS DescribeNetworkInterfaces limit
	MaxInternetGatewaysPerCall = 200 // AWS DescribeInternetGateways limit
	MaxAnalysisIdsPerCall      = 200 // AWS DescribeNetworkInsightsAnalyses limit
)

// ENIAnalysisBatchSize Batch processing configurations for network analysis.
const (
	ENIAnalysisBatchSize = 3 // ENIs processed concurrently within VPC scope analysis
)

// DefaultWebPorts Default web service ports to analyze for public exposure.
var DefaultWebPorts = []string{
	"80",   // HTTP
	"443",  // HTTPS
	"8080", // HTTP alternative
	"3000", // Development server
	"8000", // Development server
	"9000", // Development server
}
