package model

import "aws-ecs-project/grpcType"

// FlatResource represents the result structure with ID and StoreResourceFlat
type FlatResource struct {
	ID                string
	StoreResourceFlat *grpcType.StoreResourceFlat
}
