# 🔍 ECS Container Crawler

A comprehensive Go module that discovers and catalogs all Amazon ECS containers across multiple AWS regions with **concurrent processing** and **intelligent batching** for optimal performance.

## 🎯 Overview

This module systematically crawls your entire AWS ECS infrastructure to build a complete inventory of running containers. It handles the complex multi-level discovery process from regions → clusters → tasks → containers, extracting essential metadata and network interface information for each container.

## 🚀 Features

- **🌍 Multi-Region Discovery** - Concurrent scanning across all AWS regions
- **⚡ Concurrent Processing** - Parallel region, cluster, and task processing  
- **📋 Complete Pagination** - Handles unlimited clusters, tasks, and containers
- **🔗 Network Interface Extraction** - Captures ENI IDs for network analysis
- **📊 Comprehensive Metadata** - Container images, SHAs, cluster info, and ARNs
- **🛡️ Error Resilience** - Individual failures don't stop the entire crawl
- **⏱️ Performance Timing** - Built-in timing for region and overall crawl performance
- **📝 Detailed Logging** - Comprehensive progress and debug information

## 🏗️ Architecture

### **📁 Core Components**

```go
// Main entry point - coordinates multi-region crawling
func EcsCrawl(regions []string, ctx context.Context, accountID, tenantID string, cfg *aws.Config, logger zerolog.Logger) []ecscontainerdata.ContainerData

// Region-level processing with network analysis integration  
func crawlRegionContainers(regionName string, ctx context.Context, accountID, tenantID string, cfg aws.Config, logger zerolog.Logger) ([]ecscontainerdata.ContainerData, error)

// Container data structure with network optimization (from ecs_containerdata package)
type ContainerData struct {
    Name          string  // Container name
    Image         string  // Docker image
    ImageSHA      string  // Image digest/SHA
    PublicExposed bool    // Network exposure status (set by network analyzer)
    ClusterName   string  // ECS cluster name
    TaskARN       string  // ECS task ARN
    Region        string  // AWS region
    NicID         string  // Network interface ID for analysis optimization
}
```

### **🔄 Processing Flow**

```
┌─────────────────────────────────────────────────────────────┐
│                     EcsCrawl (Entry Point)                 │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────────────────────────────┐
    │              Multi-Region Concurrency                  │
    │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │
    │  │   Region 1  │ │   Region 2  │ │   Region N...   │   │
    │  │ (goroutine) │ │ (goroutine) │ │   (goroutine)   │   │
    │  └─────────────┘ └─────────────┘ └─────────────────┘   │
    └─────────────┬───────────────────────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────────────────────────────┐
    │              crawlRegionContainers                      │
    │                                                         │
    │  1. List Clusters (with pagination)                     │
    │  2. For each cluster: List Tasks (with pagination)      │
    │  3. Describe Tasks (in batches of 100)                  │
    │  4. Extract Container Data + Network Interface IDs      │
    │  5. Run Network Analysis (ecs_network_access_analyzer)  │
    └─────────────────────────────────────────────────────────┘
```

## 📋 AWS ECS API Calls Used

### **🔗 API Reference Table**

| **ECS API Method** | **Purpose** | **Pagination** | **Batch Size** | **When Called** |
|-------------------|-------------|----------------|----------------|-----------------|
| `ListClusters` | Discover ECS clusters in region | ✅ Yes (`NextToken`) | 10 per page | Once per region |
| `DescribeClusters` | Get detailed cluster information | ❌ No | 1 cluster | Per cluster found |
| `ListTasks` | Find running tasks in cluster | ✅ Yes (`NextToken`) | 100 per page | Per cluster |
| `DescribeTasks` | Get task details and containers | ❌ No | 100 per batch | Per task batch |

### **🔍 Detailed API Usage**

#### **1. Region Discovery - `ListClusters`**
```go
input := &ecs.ListClustersInput{
    MaxResults: aws.Int32(10),    // Process 10 clusters per page
    NextToken:  nextToken,       // Handle pagination
}
clustersList, err := client.ListClusters(ctx, input)
```
- **Purpose**: Discover all ECS clusters in a region
- **Pagination**: Automatic handling with `NextToken`
- **Batch Size**: 10 clusters per API call (configurable via `maxClustersPerPage`)

#### **2. Cluster Details - `DescribeClusters`**
```go
resp, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
    Clusters: []string{clusterArn},  // Single cluster per call
})
```
- **Purpose**: Get detailed cluster metadata and status
- **Batch Size**: 1 cluster per call (AWS API design)
- **Used For**: Cluster name, status, and configuration details

#### **3. Task Discovery - `ListTasks`**
```go
input := &ecs.ListTasksInput{
    Cluster:       &clusterArn,
    DesiredStatus: types2.DesiredStatusRunning,  // Only running tasks
    MaxResults:    aws.Int32(100),               // AWS maximum
    NextToken:     nextToken,                    // Pagination support
}
output, err := client.ListTasks(ctx, input)
```
- **Purpose**: Find all running tasks in a cluster
- **Filter**: Only `RUNNING` status tasks
- **Pagination**: Full support with `NextToken`
- **Batch Size**: 100 tasks per page (AWS maximum)

#### **4. Container Extraction - `DescribeTasks`**
```go
output, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
    Cluster: &clusterArn,
    Tasks:   batch,  // Up to 100 task ARNs per call
})
```
- **Purpose**: Get detailed task information including containers and network interfaces
- **Batch Processing**: 100 tasks per API call (AWS limit)
- **Critical Data**: Container definitions, network attachments, ENI IDs

## ⚙️ Configuration Constants

All API limits and batch sizes are configurable via constants in `ecs_crawl.go`:

```go
// AWS ECS API pagination and batch size limits.
const (
    maxClustersPerPage       = 10  // Clusters per ListClusters call
    maxTasksPerPage          = 100 // Tasks per ListTasks call (AWS maximum)
    taskDescriptionBatchSize = 100 // Tasks per DescribeTasks call (AWS limit)
)
```

### **🔧 Tuning for Different Environments**

**For Development/Testing:**
```go
const maxClustersPerPage = 5        // Smaller batches for easier debugging
const maxTasksPerPage = 50          // Reduced load for development
```

**For Production/High-Scale:**
```go
const maxClustersPerPage = 10       // Optimal for production throughput
const maxTasksPerPage = 100         // Maximum AWS allows
const taskDescriptionBatchSize = 100 // Full AWS batch size
```

**For Rate-Limited Accounts:**
```go
const maxClustersPerPage = 5        // Conservative limits
const maxTasksPerPage = 50          // Reduced API pressure
```

## 🚀 Concurrency Implementation

### **Multi-Level Concurrent Architecture**

#### **Level 1: Region-Level Concurrency**
```go
// All AWS regions processed simultaneously
for _, region := range regions {
    go func(regionName string) {
        regionCfg := cfg.Copy()  // Avoid race conditions
        regionCfg.Region = regionName
        
        containers, err := crawlRegionContainers(regionName, ctx, regionCfg, logger)
        resultChan <- regionResult{containers, regionName, err}
    }(region)
}

// Collect results using channel counting pattern
for i := 0; i < len(regions); i++ {
    result := <-resultChan
    allContainers = append(allContainers, result.containerDataList...)
}
```

#### **Level 2: Sequential Processing Within Region**
```go
// Within each region, process sequentially for API efficiency
clusters := listRegionClusters()           // 1. Discover clusters
for each cluster {
    tasks := listClusterTasks(cluster)      // 2. Find tasks
    taskDetails := describeClusterTasks()   // 3. Get task details (batched)
    containers := extractContainers()       // 4. Extract container data
}
```

### **🔄 Why This Concurrency Pattern?**

**✅ Region-Level Parallelism:**
- ✅ **No API Conflicts**: Each region has independent API rate limits
- ✅ **Maximum Throughput**: All regions discovered simultaneously
- ✅ **Fault Isolation**: One region failure doesn't affect others

**✅ Sequential Within Region:**
- ✅ **API Efficiency**: Respects ECS API patterns and dependencies
- ✅ **Logical Flow**: Clusters → Tasks → Containers follows natural hierarchy
- ✅ **Batch Optimization**: Uses optimal batch sizes for each API call

## 📊 Performance Characteristics

### **Scaling Analysis**

| **Scale** | **Regions** | **Clusters** | **Tasks** | **Est. Time** | **API Calls** |
|-----------|-------------|--------------|-----------|---------------|---------------|
| Small     | 3 regions   | 5 clusters   | 20 tasks  | 15-30 seconds | ~40 calls     |
| Medium    | 10 regions  | 50 clusters  | 500 tasks | 45-90 seconds | ~200 calls    |
| Large     | 20 regions  | 200 clusters | 2000 tasks| 2-4 minutes   | ~800 calls    |

### **Performance Optimizations**

#### **1. Intelligent Batching**
```go
// Tasks processed in optimal batches
for i := 0; i < len(taskArns); i += taskDescriptionBatchSize {
    batch := taskArns[i:end]  // Up to 100 tasks per API call
    taskDetails := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
        Cluster: &clusterArn,
        Tasks:   batch,
    })
}
```

#### **2. Efficient Pagination**
```go
// Automatic pagination handling
for {
    clusters, err := client.ListClusters(ctx, &ecs.ListClustersInput{
        MaxResults: aws.Int32(maxClustersPerPage),
        NextToken:  nextToken,
    })
    
    // Process this page...
    
    if clusters.NextToken == nil { break }  // No more pages
    nextToken = clusters.NextToken
}
```

#### **3. Memory Efficiency**
- ✅ **Streaming Processing**: Containers processed as discovered
- ✅ **No Large Buffers**: Results streamed through channels
- ✅ **Minimal Memory**: Only essential data stored per container

## 📈 Container Data Structure

### **🔍 ContainerData Fields**

```go
type ContainerData struct {
    // Core Container Information
    Name          string    // Container name from ECS task definition
    Image         string    // Docker image URI
    ImageSHA      string    // Image digest for security tracking
    
    // Infrastructure Context
    ClusterName   string    // ECS cluster name
    TaskARN       string    // Full ECS task ARN
    Region        string    // AWS region identifier
    
    // Network Analysis Integration
    NicID         string    // Network interface ID (ENI)
    PublicExposed bool      // Internet exposure status (set by network analyzer)
}
```

### **🔗 Network Interface Extraction**

Critical for network analysis integration:

```go
func getTaskNetworkInterface(task *types2.Task) string {
    for _, attachment := range task.Attachments {
        if aws.ToString(attachment.Type) == "ElasticNetworkInterface" {
            for _, detail := range attachment.Details {
                if aws.ToString(detail.Name) == "networkInterfaceId" {
                    return aws.ToString(detail.Value)  // ENI ID for network analysis
                }
            }
        }
    }
    return ""  // No ENI found (bridge networking, etc.)
}
```

**📌 Note**: Only Fargate and EC2 tasks with `awsvpc` networking mode have ENI attachments.

## 🔗 Integration Points

### **🔌 Network Analysis Integration**

The crawler automatically integrates with the `ecs_network_access_analyzer` package:

```go
// After container discovery, trigger network analysis
if len(regionContainersDataList) > 0 {
    logger.Info().Msgf("Starting network analysis for %d containers", len(regionContainersDataList))
    err := ecsnetworkaccessanalyzer.RunAnalysis(ctx, accountID, tenantID, cfg, regionContainersDataList, logger)
    if err != nil {
        logger.Warn().Msgf("Network analysis failed: %v", err)
    }
}
```

- ✅ **Automatic**: Network analysis runs after container discovery
- ✅ **Per-Region**: Analysis performed per region for optimal performance  
- ✅ **ENI Optimization**: Uses extracted ENI IDs for efficient analysis
- ✅ **Error Resilient**: Network analysis failures don't stop container discovery

### **📊 Export Integration**

Container data integrates with export utilities through the converters package:

```go
// Convert and export discovered containers
import "github.com/checkmarxDev/cnas-aws-connector/internal/converters"

convertedContainers := converters.ConvertEcsContainers(allContainers, logger)
// Export functionality available through the main application
```

## ⚠️ Important Notes

### **🚨 Limitations**

- **ENI Dependency**: Only containers with ENI attachments get network analysis
- **Running Tasks Only**: Only discovers `RUNNING` status tasks
- **Region Access**: Some regions may be inaccessible based on account permissions

### **🔧 Error Handling**

```go
// Resilient error handling at multiple levels
if err != nil {
    logger.Warn().Msgf("Failed to process region %s: %v", regionName, err)
    // Continue with other regions - don't fail entire crawl
}
```

- ✅ **Region Level**: Failed regions don't stop other regions
- ✅ **Cluster Level**: Failed clusters don't stop other clusters in region
- ✅ **Task Level**: Failed task descriptions don't stop container extraction

### **💡 Best Practices**

1. **🔑 IAM Permissions**: Ensure `ecs:ListClusters`, `ecs:DescribeClusters`, `ecs:ListTasks`, `ecs:DescribeTasks`
2. **⏱️ Timeouts**: Use appropriate context timeouts for large infrastructures
3. **📊 Monitoring**: Monitor API rate limits in high-scale environments
4. **🌍 Region Selection**: Filter regions based on your infrastructure footprint

## 🛠 Prerequisites

### **Required IAM Permissions**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:ListClusters",
                "ecs:DescribeClusters", 
                "ecs:ListTasks",
                "ecs:DescribeTasks"
            ],
            "Resource": "*"
        }
    ]
}
```

### **🚀 Usage Example**

```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/rs/zerolog"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"

    "github.com/checkmarxDev/cnas-aws-connector/internal/aws"
)

func main() {
    ctx := context.Background()
    logger := zerolog.New(os.Stdout)
    
    // Configure AWS
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    // Define regions to scan
    regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
    
    // Discover all containers across regions
    containers := aws.EcsCrawl(regions, ctx, "accountID", "tenantID", &cfg, logger)
    
    fmt.Printf("Discovered %d containers across %d regions\n", len(containers), len(regions))
}
```

## 📊 Sample Output

### **Console Logging**
```
🔍 ECS Crawler: Creating ECS client for region us-east-1...
🔍 ECS Crawler: Listing containers in region us-east-1...
🔍 ECS Crawler: ECS 3 clusters out of 10 requested per page
🔍 ECS Crawler:      Describing cluster details: 1). clusterArn: arn:aws:ecs:us-east-1:123:cluster/prod-cluster
🔍 ECS Crawler: Processing cluster: prod-cluster
🔍 ECS Crawler:      Listing containers in cluster: prod-cluster
🔍 ECS Crawler:      Found 15 running tasks
🔍 ECS Crawler:           Task 1: arn:aws:ecs:us-east-1:123:task/abc123
🔍 ECS Crawler:           List Containers (2):
🔍 ECS Crawler:             1. Container Name: web-server
🔍 ECS Crawler:             2. Container Name: sidecar-proxy
🔍 ECS Crawler:      Found 30 containers across 15 tasks in cluster prod-cluster
🔍 ECS Crawler: Found 30 containers in region us-east-1
🔍 ECS Crawler: Starting network analysis for 30 containers in region us-east-1
🔍 ECS Crawler: Network analysis completed for region us-east-1
🔍 ECS Crawler: Crawl region us-east-1 took 45.2s to complete!
🔍 ECS Crawler: Completed processing 3 regions, found 75 total containers
🔍 ECS Crawler: Crawl took 52.1s to complete!
```

### **Container Data Example**
```go
ecscontainerdata.ContainerData{
    Name:          "web-server",
    Image:         "nginx:1.21",
    ImageSHA:      "sha256:abc123...",
    PublicExposed: true,  // Set by network analyzer
    ClusterName:   "prod-cluster",
    TaskARN:       "arn:aws:ecs:us-east-1:123456789012:task/abc123",
    Region:        "us-east-1",
    NicID:         "eni-0123456789abcdef0",  // For network analysis
}
```

---

**Built with ❤️ for comprehensive ECS infrastructure discovery and security analysis.**
