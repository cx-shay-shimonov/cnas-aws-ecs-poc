package grpcType

// ResourceType represents the type of the resource
type ResourceType int32

const (
	ResourceType_CONTAINER ResourceType = 0 // Resource is a container
)

// ResourceGroupType represents the type of the resource group
type ResourceGroupType string

const (
	ResourceGroupType_ECS ResourceGroupType = "ECS"
)

type Correlation struct {
}

// StoreResourceFlat represents a flattened resource for storage
type StoreResourceFlat struct {
	Name          string
	Type          ResourceType
	Image         string
	ImageSha      string // todo: Implement image SHA extraction
	Metadata      map[string]string
	PublicExposed bool
	Correlation   *Correlation
	ClusterName   string
	ClusterType   ResourceGroupType
	ProviderId    string
	Region        string
}
