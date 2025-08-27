// Package common provides shared error types and error handling utilities for the AWS crawler modules.
// This standardizes error handling patterns across ECS and EKS components.
package common

import "fmt"

// CrawlError represents a standardized error from AWS crawling operations.
type CrawlError struct {
	Component string // "ECS", "EKS", "NetworkAnalyzer", etc.
	Region    string // AWS region where error occurred
	Operation string // Operation that failed
	Err       error  // Underlying error
}

// Error implements the error interface.
func (e *CrawlError) Error() string {
	if e.Region != "" {
		return fmt.Sprintf("%s/%s: %s failed: %v", e.Component, e.Region, e.Operation, e.Err)
	}

	return fmt.Sprintf("%s: %s failed: %v", e.Component, e.Operation, e.Err)
}

// Unwrap returns the underlying error for error unwrapping.
func (e *CrawlError) Unwrap() error {
	return e.Err
}

// NewCrawlError creates a new CrawlError with the specified parameters.
func NewCrawlError(component, region, operation string, err error) *CrawlError {
	return &CrawlError{
		Component: component,
		Region:    region,
		Operation: operation,
		Err:       err,
	}
}

// NewECSError creates a new CrawlError for ECS operations.
func NewECSError(region, operation string, err error) *CrawlError {
	return NewCrawlError("ECS", region, operation, err)
}
