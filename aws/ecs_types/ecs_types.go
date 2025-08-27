// Package ecs_types defines data structures for representing ECS container metadata and network information.
// It provides the core ContainerData type used throughout the ECS analysis system.
package ecs_types

// NetworkAnalysisApproach represents the type of network analysis to perform.
type NetworkAnalysisApproach string

// Network analysis approach constants.
const (
	ApproachVPC   NetworkAnalysisApproach = "vpc"   // Optimized VPC Reachability Analyzer with batch processing
	ApproachScope NetworkAnalysisApproach = "scope" // Account-wide Network Access Scope
)

// ContainerData represents metadata and network information for an ECS container.
type ContainerData struct {
	Name          string
	Image         string
	ImageSHA      string
	PublicExposed bool
	ClusterName   string
	TaskARN       string
	Region        string
	NicID         string // Network interface ID for optimization
}
