// Package ecsnetworkaccessanalyzer defines configuration constants and types for network analysis operations.
// This file contains compile-time configuration for analysis approaches, timeouts, and AWS API limits.
package ecsnetworkaccessanalyzer

import (
	"aws-ecs-project/aws/common"
)

// Use centralized constants from common package
const (
	pollingInterval            = common.PollingInterval
	vpcAnalysisTimeout         = common.VPCAnalysisTimeout
	scopeAnalysisTimeout       = common.ScopeAnalysisTimeout
	maxENIsPerCall             = common.MaxENIsPerCall
	maxInternetGatewaysPerCall = common.MaxInternetGatewaysPerCall
	maxAnalysisIdsPerCall      = common.MaxAnalysisIdsPerCall
	eniAnalysisBatchSize       = common.ENIAnalysisBatchSize
)

// Use centralized default web ports from common package.
var defaultWebPorts = common.DefaultWebPorts
