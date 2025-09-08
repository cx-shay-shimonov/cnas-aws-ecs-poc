# 🏗️ AWS Infrastructure Crawler Module

A comprehensive Go module for discovering and analyzing AWS infrastructure components with a focus on security assessment and public exposure detection.

## 🎯 **Overview**

This module provides a unified interface for crawling AWS ECS and EKS resources across multiple regions, with integrated network analysis to determine public exposure of containers and workloads.

## 🏗️ **Architecture**

```
internal/aws/
├── common/                    # Shared utilities and types
│   ├── constants.go          # Centralized configuration constants
│   ├── errors.go             # Standardized error types
│   └── *_test.go             # Comprehensive tests
├── ecs_crawl.go              # ECS container discovery
├── eks-crawl.go              # EKS cluster discovery
├── crawler.go                # Main orchestration (not modified)
├── eks-network-access-analyzer.go  # EKS network analysis (not modified)
├── ecs_network_access_analyzer/    # ECS network analysis
│   ├── ecs_network_analyzer.go     # Main analyzer interface
│   ├── network_analysis_*.go       # Analysis implementations
│   └── network_analysis_constants.go # Analysis-specific constants
├── ecs_types/                # ECS data structures
│   └── ecs_types.go          # Container and analysis types
└── docs/                     # Documentation
    ├── ECS-CRAWL-README.md    # Detailed ECS crawler docs
    └── ECS-NETWORK-ANALYZER-README.md # Network analysis docs
```

## 🚀 **Key Features**

### **Unified Infrastructure Discovery**
- **Multi-Region Support**: Concurrent scanning across all AWS regions
- **Dual Service Support**: Both ECS containers and EKS clusters
- **Comprehensive Metadata**: Images, SHAs, cluster info, network interfaces

### **Advanced Network Analysis**
- **Dual Analysis Approaches**: VPC Reachability Analyzer and Network Access Scope
- **Public Exposure Detection**: Authoritative security assessments using AWS services
- **Batch Processing**: Optimized API usage with intelligent batching

### **Production-Ready Quality**
- **Standardized Error Handling**: Consistent error types across all components
- **Comprehensive Testing**: Unit tests for core functionality
- **Centralized Configuration**: Single source of truth for constants
- **Performance Optimized**: Concurrent processing and efficient API usage

## 🔧 **Usage**

### **Basic Crawler Usage**
```go
import (
    "context"
    "github.com/checkmarxDev/cnas-aws-connector/internal/aws"
    ecsTypes "github.com/checkmarxDev/cnas-aws-connector/internal/aws/ecs_types"
)

func main() {
    ctx := context.Background()
    
    // Configure crawler parameters
    clusters, exposedPods, containers, err := aws.Crawl(
        ctx,
        "arn:aws:iam::123456789012:role/CrawlerRole", // roleArn
        "tenant-123",                                   // tenantID
        "123456789012",                                // accountID
        true,                                          // isK8SAuthorizationEnabled
        true,                                          // isECSDiscoveryEnabled
        true,                                          // isEcsAwsCrawlerEnabled
        logger,                                        // cnasLogger
    )
    
    if err != nil {
        // Handle error (standardized error types)
        log.Fatal(err)
    }
    
    // Process results
    fmt.Printf("Found %d EKS clusters\n", len(clusters))
    fmt.Printf("Found %d ECS containers\n", len(containers))
    fmt.Printf("Found %d exposed pods\n", len(exposedPods))
}
```

### **ECS-Only Crawling**
```go
import (
    ecsTypes "github.com/checkmarxDev/cnas-aws-connector/internal/aws/ecs_types"
)

func crawlECSOnly() {
    regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
    
    containers := aws.EcsCrawl(
        regions,
        ctx,
        accountID,
        tenantID,
        &awsConfig,
        logger,
    )
    
    // Process containers with network analysis results
    for _, container := range containers {
        if container.PublicExposed {
            fmt.Printf("⚠️  Container %s is publicly exposed!\n", container.Name)
        }
    }
}
```

### **Network Analysis Configuration**
```go
// Configure analysis approach in ecs_crawl.go
const networkAnalysisApproach = ecsTypes.ApproachVPC   // Recommended for container analysis
// const networkAnalysisApproach = ecsTypes.ApproachScope  // For enterprise compliance
```

## 📊 **Error Handling**

The module uses standardized error types from the `common` package:

```go
import "github.com/checkmarxDev/cnas-aws-connector/internal/aws/common"

// Handle specific error types
if crawlErr, ok := err.(*common.CrawlError); ok {
    fmt.Printf("Component: %s, Region: %s, Operation: %s\n", 
        crawlErr.Component, crawlErr.Region, crawlErr.Operation)
}

// Or use error factories
ecsErr := common.NewECSError("us-east-1", "list clusters", originalErr)
netErr := common.NewNetworkAnalysisError("eu-west-1", "VPC analysis", originalErr)
```

## ⚙️ **Configuration**

### **Centralized Constants**
All configuration is centralized in `common/constants.go`:

```go
import "github.com/checkmarxDev/cnas-aws-connector/internal/aws/common"

// ECS API limits
common.MaxClustersPerPage       // 10
common.MaxTasksPerPage          // 100
common.TaskDescriptionBatchSize // 100

// Network analysis timeouts
common.PollingInterval          // 5 seconds
common.VPCAnalysisTimeout      // 2 minutes
common.ScopeAnalysisTimeout    // 10 minutes

// AWS API batch sizes
common.MaxENIsPerCall          // 200
common.MaxAnalysisIdsPerCall   // 200
```

### **Network Analysis Approaches**

| Approach | Use Case | Performance | Cost |
|----------|----------|-------------|------|
| **VPC** | Container exposure detection | 2-25 minutes | $0.10 per container |
| **Scope** | Enterprise compliance audits | 20-70 minutes | $1 per account |

## 🧪 **Testing**

Run the comprehensive test suite:

```bash
# Run all tests
go test ./internal/aws/...

# Run with coverage
go test -cover ./internal/aws/...

# Run specific component tests
go test ./internal/aws/common/...
go test ./internal/aws -run TestECS
```

## 📚 **Documentation**

Detailed documentation is available in the `docs/` directory:

- **[ECS Crawler Guide](docs/ECS-CRAWL-README.md)** - Comprehensive ECS crawler documentation
- **[Network Analyzer Guide](docs/ECS-NETWORK-ANALYZER-README.md)** - Network analysis approaches and optimization

## 🔍 **Package Structure**

### **Core Packages**
- **`common/`** - Shared utilities, constants, and error types
- **`ecs_types/`** - ECS-specific data structures and enums
- **`ecs_network_access_analyzer/`** - Network analysis implementations

### **Main Files**
- **`crawler.go`** - Main orchestration (EKS + ECS) 
- **`ecs_crawl.go`** - ECS container discovery and crawling
- **`eks-crawl.go`** - EKS cluster discovery (not modified)
- **`eks-network-access-analyzer.go`** - EKS network analysis (not modified)

## 🎯 **Improvements Made**

### **✅ Structural Fixes**
- **Eliminated duplicate type definitions** across files
- **Centralized constants** in common package
- **Standardized import aliasing** using `ecsTypes`
- **Consistent error handling** with structured error types

### **✅ Code Quality**
- **Comprehensive test coverage** for new components
- **Proper documentation structure** with dedicated docs directory
- **Standardized function signatures** and parameter ordering
- **Improved error messages** with contextual information

### **✅ Maintainability**
- **Single source of truth** for configuration constants
- **Modular architecture** with clear separation of concerns
- **Consistent coding patterns** across all components
- **Future-proof design** for easy extension

## 🚦 **Migration Notes**

If upgrading from previous versions:

1. **Import Changes**: Update imports to use `ecsTypes` alias consistently
2. **Constants**: Replace local constants with `common` package references
3. **Error Handling**: Update error handling to use standardized `CrawlError` types
4. **Documentation**: Refer to new documentation structure in `docs/` directory

## 🔐 **Required IAM Permissions**

This module requires comprehensive AWS permissions to perform infrastructure discovery and network analysis across multiple services. Below are the complete IAM permissions needed:

### **Complete IAM Policy**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeRegions",
                "ec2:DescribeNetworkInterfaces", 
                "ec2:DescribeInternetGateways"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecs:ListClusters",
                "ecs:DescribeClusters",
                "ecs:ListTasks",
                "ecs:DescribeTasks"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "eks:ListClusters",
                "eks:DescribeCluster",
                "eks:CreateAccessEntry",
                "eks:AssociateAccessPolicy",
                "eks:ListAccessEntries",
                "eks:ListAssociatedAccessPolicies"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInsightsPath",
                "ec2:StartNetworkInsightsAnalysis",
                "ec2:DescribeNetworkInsightsAnalyses",
                "ec2:DeleteNetworkInsightsPath"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInsightsAccessScope",
                "ec2:StartNetworkInsightsAccessScopeAnalysis",
                "ec2:DescribeNetworkInsightsAccessScopes",
                "ec2:DescribeNetworkInsightsAccessScopeAnalyses",
                "ec2:GetNetworkInsightsAccessScopeAnalysisFindings",
                "ec2:DeleteNetworkInsightsAccessScopeAnalysis",
                "ec2:DeleteNetworkInsightsAccessScope"
            ],
            "Resource": "*"
        }
    ]
}
```

### **Permission Categories**

#### **🔑 Authentication & Role Management**
- `sts:AssumeRole` - Cross-account role assumption for multi-account scanning
- `sts:GetCallerIdentity` - Identity verification

#### **🌍 Infrastructure Discovery**
- `ec2:DescribeRegions` - Multi-region discovery
- `ec2:DescribeNetworkInterfaces` - ENI information for containers/pods
- `ec2:DescribeInternetGateways` - Internet connectivity analysis

#### **📦 ECS Container Discovery**
- `ecs:ListClusters` - Discover ECS clusters
- `ecs:DescribeClusters` - Cluster metadata
- `ecs:ListTasks` - Running tasks discovery  
- `ecs:DescribeTasks` - Container and network interface extraction

#### **☸️ EKS Cluster & Pod Discovery**
- `eks:ListClusters` - Discover EKS clusters
- `eks:DescribeCluster` - Cluster configuration and endpoints
- `eks:CreateAccessEntry` - Kubernetes RBAC integration
- `eks:AssociateAccessPolicy` - Policy association for cluster access
- `eks:ListAccessEntries` - Existing access management
- `eks:ListAssociatedAccessPolicies` - Policy management

#### **🔍 VPC Network Analysis (VPC Approach)**
- `ec2:CreateNetworkInsightsPath` - Point-to-point reachability paths
- `ec2:StartNetworkInsightsAnalysis` - Execute reachability analysis
- `ec2:DescribeNetworkInsightsAnalyses` - Poll analysis results
- `ec2:DeleteNetworkInsightsPath` - Cleanup analysis resources

#### **🏢 Network Access Scope Analysis (Scope Approach)**
- `ec2:CreateNetworkInsightsAccessScope` - Account-wide network scopes
- `ec2:StartNetworkInsightsAccessScopeAnalysis` - Comprehensive network analysis
- `ec2:DescribeNetworkInsightsAccessScopes` - Scope discovery and management
- `ec2:DescribeNetworkInsightsAccessScopeAnalyses` - Analysis status monitoring
- `ec2:GetNetworkInsightsAccessScopeAnalysisFindings` - Retrieve analysis results
- `ec2:DeleteNetworkInsightsAccessScopeAnalysis` - Cleanup analysis resources
- `ec2:DeleteNetworkInsightsAccessScope` - Cleanup scope resources

### **💰 Cost Considerations**

#### **VPC Approach Costs:**
- **Network Insights Path Analysis**: $0.10 per path analysis
- **Typical Cost**: ~$0.10 per container analyzed

#### **Scope Approach Costs:**
- **Network Access Scope Analysis**: $1.00 per scope analysis  
- **Typical Cost**: ~$1 per account (covers unlimited containers)

### **🔒 Security Best Practices**

1. **Principle of Least Privilege**: Only grant permissions needed for your specific use case
2. **Cross-Account Roles**: Use dedicated roles for scanning external accounts
3. **External ID**: Always use tenant-specific external IDs for role assumption
4. **Resource Cleanup**: The tool automatically cleans up temporary analysis resources
5. **Network Analysis**: All network analysis is read-only - no infrastructure changes

### **📋 Optional Permissions**

For enhanced functionality, you may also want to include:

```json
{
    "Effect": "Allow", 
    "Action": [
        "eks:DescribeNodegroup",
        "eks:ListNodegroups",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs"
    ],
    "Resource": "*"
}
```

These permissions enable deeper infrastructure analysis and troubleshooting capabilities.

## 🤝 **Contributing**

When contributing to this module:

1. **Follow Conventions**: Use standardized error handling and import aliasing
2. **Add Tests**: Include comprehensive tests for new functionality
3. **Update Constants**: Add new configuration to `common/constants.go`
4. **Document Changes**: Update relevant documentation in `docs/`
5. **IAM Updates**: If adding new AWS API calls, update the IAM permissions section

---

**Built with ❤️ for scalable, maintainable AWS infrastructure discovery.**
