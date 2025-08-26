// Package ecscontainerdata defines data structures for representing ECS container metadata and network information.
// It provides the core ContainerData type used throughout the ECS analysis system.
package ecscontainerdata

// ContainerData represents metadata and network information for an ECS container.
type ContainerData struct {
	Name          string
	Image         string
	ImageSHA      string
	PublicExposed bool
	ClusterName   string

	TaskARN string
	Region  string
	NicID   string // Network interface ID for optimization
}
