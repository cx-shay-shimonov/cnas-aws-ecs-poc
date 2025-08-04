package aws

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"strconv"
	"sync"
	"time"

	"aws-ecs-project/model"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	types2 "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/uuid"

	"aws-ecs-project/grpcType"
)

type ContainerData struct {
	Name          string
	Type          grpcType.ResourceType
	Image         string
	ImageSHA      string
	PublicExposed bool
	ClusterName   string
	ClusterType   grpcType.ResourceGroupType

	// Container-specific fields only (no duplicates from StoreResourceFlat)
	Status        string
	RuntimeID     string
	TaskARN       string
	TaskStatus    string
	HostPort      int
	ContainerPort int
	Protocol      string
	PrivateIP     string
	Region        string
}

// NetworkExposureAnalysis contains detailed network exposure information
type NetworkExposureAnalysis struct {
	IsPubliclyExposed bool
	ExposureReasons   []string
	NetworkMode       string
	HasPublicIP       bool
	IsInPublicSubnet  bool
	SecurityGroups    []string // todo: is this needed?
	OpenPorts         []string
	LoadBalancers     []string
	PrivateIPs        []string
	PublicIPs         []string
	NetworkInterfaces []string
}

const maxClustersPerPage = 10
const maxTasksPerPage = 100
const taskDescriptionBatchSize = 100 // AWS limit for DescribeTasks

// ENIAnalysis contains ENI-specific analysis results.
type ENIAnalysis struct {
	HasPublicIP      bool
	IsInPublicSubnet bool
	SecurityGroups   []string // todo: is this needed?
	OpenPorts        []string
	PrivateIPs       []string
	PublicIPs        []string
}

func EcsCrawlUsingWaitGroupAndMutex(regions []string, ctx context.Context, cfg *aws.Config, cnasLogger zerolog.Logger) []model.FlatResource {

	defer ecsCrawlTimer(cnasLogger)()
	// Process containers from all regions in parallel
	allResources := make([]model.FlatResource, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, region := range regions {
		wg.Add(1)
		go func(regionName string) {
			defer wg.Done()

			// Create a copy of config for this region to avoid race conditions
			regionCfg := cfg.Copy()
			regionCfg.Region = regionName

			regionResources, err := crawlRegionResources(regionName, ctx, regionCfg, cnasLogger)
			if err != nil {
				cnasLogger.Warn().Msgf("🐳 ECS Crawler: Failed to process region %s: %v", regionName, err)
				return
			}

			// Safely append results
			mu.Lock()
			allResources = append(allResources, regionResources...)
			mu.Unlock()
		}(region)
	}

	// Wait for all regions to complete
	wg.Wait()
	cnasLogger.Info().Msgf("🐳 ECS Crawler: Completed processing %d regions, found %d total resources", len(regions), len(allResources))
	return allResources
}

// EcsCrawl Alternative implementation using channels instead of mutex and waitgroup
func EcsCrawl(regions []string, ctx context.Context, cfg *aws.Config, cnasLogger zerolog.Logger) []model.FlatResource {
	defer ecsCrawlTimer(cnasLogger)()

	// Create channels for coordination
	type regionResult struct {
		resources []model.FlatResource
		region    string
		err       error
	}

	resultChan := make(chan regionResult, len(regions))

	// Start workers for each region
	for _, region := range regions {
		go func(regionName string) {
			// Create a copy of config for this region to avoid race conditions
			regionCfg := cfg.Copy()
			regionCfg.Region = regionName

			regionResources, err := crawlRegionResources(regionName, ctx, regionCfg, cnasLogger)
			if err != nil {
				cnasLogger.Warn().Msgf("🐳 ECS Crawler: Failed to process region %s: %v", regionName, err)
				resultChan <- regionResult{nil, regionName, err}
				return
			}

			resultChan <- regionResult{regionResources, regionName, nil}
		}(region)
	}

	// Collect results
	allResources := make([]model.FlatResource, 0)
	for i := 0; i < len(regions); i++ {
		result := <-resultChan
		if result.err == nil {
			allResources = append(allResources, result.resources...)
		}
	}

	cnasLogger.Info().Msgf("🐳 ECS Crawler: Completed processing %d regions, found %d total resources", len(regions), len(allResources))
	return allResources
}

// EcsCrawlWithWorkerPool Option 2: Worker Pool Pattern
func EcsCrawlWithWorkerPool(regions []string, ctx context.Context, cfg *aws.Config, cnasLogger zerolog.Logger) []model.FlatResource {
	defer ecsCrawlTimer(cnasLogger)()

	// Create channels
	jobs := make(chan string, len(regions))
	results := make(chan []model.FlatResource, len(regions))
	errors := make(chan error, len(regions))

	// Number of workers (can be adjusted based on needs)
	numWorkers := min(len(regions), 10) // Max 10 concurrent workers

	// Start workers
	for w := 0; w < numWorkers; w++ {
		go func() {
			for regionName := range jobs {
				// Create a copy of config for this region
				regionCfg := cfg.Copy()
				regionCfg.Region = regionName

				regionResources, err := crawlRegionResources(regionName, ctx, regionCfg, cnasLogger)
				if err != nil {
					cnasLogger.Warn().Msgf("🐳 ECS Crawler: Failed to process region %s: %v", regionName, err)
					errors <- err
					results <- nil
					continue
				}

				errors <- nil
				results <- regionResources
			}
		}()
	}

	// Send jobs
	for _, region := range regions {
		jobs <- region
	}
	close(jobs)

	// Collect results
	allResources := make([]model.FlatResource, 0)
	for i := 0; i < len(regions); i++ {
		err := <-errors
		result := <-results
		if err == nil && result != nil {
			allResources = append(allResources, result...)
		}
	}

	cnasLogger.Info().Msgf("🐳 ECS Crawler: Completed processing %d regions, found %d total resources", len(regions), len(allResources))
	return allResources
}

// EcsCrawlWithPipeline Option 3: Pipeline Pattern with Done Channel
func EcsCrawlWithPipeline(regions []string, ctx context.Context, cfg *aws.Config, cnasLogger zerolog.Logger) []model.FlatResource {
	defer ecsCrawlTimer(cnasLogger)()

	// Create channels
	resultChan := make(chan []model.FlatResource)
	done := make(chan struct{})

	// Result collector goroutine
	allResources := make([]model.FlatResource, 0)
	go func() {
		defer close(done)
		for resources := range resultChan {
			if resources != nil {
				allResources = append(allResources, resources...)
			}
		}
	}()

	// Start workers
	for _, region := range regions {
		go func(regionName string) {
			defer func() {
				// Signal completion by sending to result channel
				resultChan <- nil
			}()

			// Create a copy of config for this region
			regionCfg := cfg.Copy()
			regionCfg.Region = regionName

			regionResources, err := crawlRegionResources(regionName, ctx, regionCfg, cnasLogger)
			if err != nil {
				cnasLogger.Warn().Msgf("🐳 ECS Crawler: Failed to process region %s: %v", regionName, err)
				return
			}

			resultChan <- regionResources
		}(region)
	}

	// Wait for all workers to complete
	completedWorkers := 0
	for completedWorkers < len(regions) {
		select {
		case resources := <-resultChan:
			if resources == nil {
				completedWorkers++
			} else {
				allResources = append(allResources, resources...)
			}
		}
	}

	close(resultChan)
	<-done // Wait for collector to finish

	cnasLogger.Info().Msgf("🐳 ECS Crawler: Completed processing %d regions, found %d total resources", len(regions), len(allResources))
	return allResources
}

// EcsCrawlWithContext Option 4: Simple Channel with Context Cancellation
func EcsCrawlWithContext(regions []string, ctx context.Context, cfg *aws.Config, cnasLogger zerolog.Logger) []model.FlatResource {
	defer ecsCrawlTimer(cnasLogger)()

	// Create a buffered channel to collect all results
	resultChan := make(chan []model.FlatResource, len(regions))

	// Start goroutines for each region
	for _, region := range regions {
		go func(regionName string) {
			// Create a copy of config for this region
			regionCfg := cfg.Copy()
			regionCfg.Region = regionName

			regionResources, err := crawlRegionResources(regionName, ctx, regionCfg, cnasLogger)
			if err != nil {
				cnasLogger.Warn().Msgf("🐳 ECS Crawler: Failed to process region %s: %v", regionName, err)
				resultChan <- nil // Send nil to indicate completion even on error
				return
			}

			// Send results or nil if context is cancelled
			select {
			case resultChan <- regionResources:
			case <-ctx.Done():
				cnasLogger.Warn().Msgf("🐳 ECS Crawler: Context cancelled for region %s", regionName)
				resultChan <- nil
			}
		}(region)
	}

	// Collect results with timeout handling
	allResources := make([]model.FlatResource, 0)
	for i := 0; i < len(regions); i++ {
		select {
		case resources := <-resultChan:
			if resources != nil {
				allResources = append(allResources, resources...)
			}
		case <-ctx.Done():
			cnasLogger.Warn().Msg("🐳 ECS Crawler: Context cancelled, stopping collection")
			break
		}
	}

	cnasLogger.Info().Msgf("🐳 ECS Crawler: Completed processing %d regions, found %d total resources", len(regions), len(allResources))
	return allResources
}

// Helper function for min (since Go < 1.21 doesn't have built-in min for int)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func crawlRegionResources(regionName string, ctx context.Context, cfg aws.Config, cnasLogger zerolog.Logger) ([]model.FlatResource, error) {

	defer ecsCrawlRegionTimer(cnasLogger, regionName)()

	ecsClient, ec2Client /*, elbClient*/ := createRegionClients(regionName, cfg, cnasLogger)
	totalContainers := 0

	// List containers in this region
	cnasLogger.Info().Msgf("🐳 ECS Crawler: 🐳 Listing containers in region %s...", regionName)

	regionClustersList, err := listRegionClusters(ctx, ecsClient, cnasLogger)
	if err != nil {
		cnasLogger.Err(err).Msgf("🐳 ECS Crawler: failed to list client in region: %s.", regionName)
		return nil, err
	}
	regionContainersDataList, err := listRegionContainersData(ctx, ecsClient, regionClustersList, regionName, cnasLogger)

	if err != nil {
		cnasLogger.Err(err).Msgf("🐳 ECS Crawler: operation failed in region %s: %v", regionName, err)
		return nil, err
	}

	cnasLogger.Info().Msgf(
		"🐳 ECS Crawler: 📊 Found %d containers in region %s",
		len(regionContainersDataList),
		regionName,
	)
	totalContainers += len(regionContainersDataList)

	// Perform network analysis and generate flat resources
	if len(regionContainersDataList) == 0 {
		cnasLogger.Warn().Msgf("🐳 ECS Crawler: 📝 No containers found in region %s", regionName)
		return nil, fmt.Errorf("no containers found in region %s", regionName)
	}
	cnasLogger.Info().Msgf("🐳 ECS Crawler: 🔍 Analyzing network exposure for region %s...", regionName)
	// container by task ARN for network analysis
	taskArnContainerMap := createTaskArnContainerMap(regionContainersDataList)

	// Analyze each container task's network exposure
	taskArnContainerNetworkMap := createTaskArnContainerNetworkMap(
		ctx,
		ecsClient,
		ec2Client,
		//elbClient,
		taskArnContainerMap,
		cnasLogger,
	)

	regionResourcesList := extractResources(regionContainersDataList, taskArnContainerNetworkMap, cnasLogger)

	cnasLogger.Info().Msgf(
		"🐳 ECS Crawler: ✅ Successfully analyzed %d containers in region %s",
		len(regionResourcesList),
		regionName,
	)

	return regionResourcesList, nil
}

func extractResources(
	containersData []ContainerData,
	taskArnContainerNetworkMap map[string]*NetworkExposureAnalysis,
	cnasLogger zerolog.Logger,
) []model.FlatResource {
	allResourcesList := make([]model.FlatResource, 0, len(containersData))
	// Map each containerData to FlatResourceResult with enhanced network data
	for _, containerData := range containersData {
		// Get network analysis for this containerData's task
		containerNetworkAnalysis := taskArnContainerNetworkMap[containerData.TaskARN]

		setContainerNetworkPubliclyExposed(&containerData, containerNetworkAnalysis)

		resourceFlatContainer := containerToResource(containerData)

		allResourcesList = append(allResourcesList, resourceFlatContainer)
	}

	cnasLogger.Info().Msgf(
		"🐳 ECS Crawler: 📄 MapAWSToFlatResource Results Summary: Generated %d flat resources",
		len(allResourcesList),
	)

	return allResourcesList
}

func createRegionClients(
	regionName string,
	cfg aws.Config,
	cnasLogger zerolog.Logger,
) (ecsClient *ecs.Client, ec2Client *ec2.Client /*, elbClient *elasticloadbalancingv2.Client*/) {
	// Create clients for this region
	cnasLogger.Info().Msgf("🐳 ECS Crawler: 🔧 Creating AWS clients for region %s...", regionName)
	ecsClient = ecs.NewFromConfig(cfg)
	ec2Client = ec2.NewFromConfig(cfg)
	//elbClient = elasticloadbalancingv2.NewFromConfig(cfg)

	return ecsClient, ec2Client // , elbClient
}

func listRegionClusters(
	ctx context.Context,
	client *ecs.Client,
	cnasLogger zerolog.Logger,
) ([]*types2.Cluster, error) {

	var allClusters []*types2.Cluster
	var nextToken *string
	// Paginate through clusters
	for {
		input := &ecs.ListClustersInput{
			MaxResults: aws.Int32(maxClustersPerPage), // List up to 10 clusters
			NextToken:  nextToken,
		}

		clustersList, err := client.ListClusters(ctx, input)
		if err != nil {
			cnasLogger.Err(err).Msgf("🐳 ECS Crawler: failed to list ECS clusters")
			return nil, err
		}

		cnasLogger.Info().Msgf(
			"🐳 ECS Crawler: ECS %d clusters out of %d requested per page",
			len(clustersList.ClusterArns),
			*input.MaxResults,
		)

		// Success - print results
		for i, clusterArn := range clustersList.ClusterArns {

			// Describe each cluster
			cnasLogger.Info().Msgf(
				"🐳 ECS Crawler:      🔍 Describing cluster details:  %d). clusterArn: %s",
				i+1,
				clusterArn,
			)

			cluster, err := describeCluster(ctx, client, clusterArn)
			if err != nil {
				cnasLogger.Warn().Msgf(
					"🐳 ECS Crawler:      ❌ Failed to describe cluster %s: %v",
					clusterArn,
					err,
				)
				continue
			}

			if cluster == nil {
				cnasLogger.Warn().Msgf("🐳 ECS Crawler:      ⚠️ No cluster data returned")
				continue
			}
			allClusters = append(allClusters, cluster)
		}
		if clustersList.NextToken == nil {
			break
		}
		nextToken = clustersList.NextToken
	}

	return allClusters, nil
}

func listRegionContainersData(
	ctx context.Context,
	client *ecs.Client,
	clusters []*types2.Cluster,
	region string,
	cnasLogger zerolog.Logger,
) ([]ContainerData, error) {

	allContainersDataList := make([]ContainerData, 0)
	for _, cluster := range clusters {
		cnasLogger.Info().Msgf("🐳 ECS Crawler: 🔍 Processing cluster: %s", aws.ToString(cluster.ClusterName))
		clusterContainersDataList, err := listContainersInCluster(ctx, client, cluster, region, cnasLogger)
		if err != nil {
			cnasLogger.Err(err).Msgf(
				"🐳 ECS Crawler:      ❌ Failed to list containers in cluster %s: %v",
				aws.ToString(cluster.ClusterName),
				err,
			)
			return allContainersDataList, err
		}
		allContainersDataList = append(allContainersDataList, clusterContainersDataList...)
	}

	return allContainersDataList, nil
}

func listContainersInCluster(
	ctx context.Context,
	client *ecs.Client,
	cluster *types2.Cluster,
	region string,
	cnasLogger zerolog.Logger,
) ([]ContainerData, error) {
	clusterName := aws.ToString(cluster.ClusterName)

	var containersDataList []ContainerData

	clusterTasks, err := listClusterTasks(ctx, client, cluster, cnasLogger)
	if err != nil {
		return containersDataList, err
	}

	totalContainers := 0

	for taskIndex, task := range clusterTasks {
		cnasLogger.Info().Msgf("🐳 ECS Crawler:        📋 Task %d: %s", taskIndex+1, aws.ToString(task.TaskArn))
		cnasLogger.Info().Msgf("🐳 ECS Crawler:           Status: %s", aws.ToString(task.LastStatus))
		cnasLogger.Info().Msgf("🐳 ECS Crawler:           Desired Status: %s", aws.ToString(task.DesiredStatus))

		if task.TaskDefinitionArn != nil {
			cnasLogger.Info().Msgf(
				"🐳 ECS Crawler:           Task Definition: %s",
				aws.ToString(task.TaskDefinitionArn),
			)
		}

		if len(task.Containers) == 0 {
			cnasLogger.Info().Msgf("🐳 ECS Crawler:           ⚠️ No containersDataList found in this task")
			continue
		}

		cnasLogger.Info().Msgf("🐳 ECS Crawler:           📦 Containers (%d):", len(task.Containers))

		for containerIndex, container := range task.Containers {
			// Set region for each container
			totalContainers++
			cnasLogger.Info().Msgf(
				"🐳 ECS Crawler:             %d. Container Name: %s",
				containerIndex+1,
				aws.ToString(container.Name),
			)

			if container.TaskArn != nil {
				cnasLogger.Info().Msgf("🐳 ECS Crawler:                Task ARN: %s", aws.ToString(container.TaskArn))
			}

			// Create container data object WITHOUT adding to CSV/JSON yet
			containerData := createContainerData(cluster, &task, &container, nil, region)

			containersDataList = append(containersDataList, containerData)
		}
		cnasLogger.Info().Msgf("🐳 ECS Crawler: \n")
	}

	// Summary and logging
	cnasLogger.Info().Msgf(
		"🐳 ECS Crawler:      ✅ Found %d containersDataList across %d tasks in cluster %s",
		totalContainers,
		len(clusterTasks),
		clusterName,
	)

	return containersDataList, nil
}

func listClusterTasks(ctx context.Context, client *ecs.Client, cluster *types2.Cluster, cnasLogger zerolog.Logger) ([]types2.Task, error) {
	clusterArn := aws.ToString(cluster.ClusterArn)
	clusterName := aws.ToString(cluster.ClusterName)

	cnasLogger.Info().Msgf("🐳 ECS Crawler:      🔍 Listing containersDataList in cluster: %s", clusterName)

	// Get tasks in the cluster
	taskArnList, err := listClusterTasksArns(ctx, client, clusterArn)
	if err != nil {
		cnasLogger.Err(err).Msgf(
			"🐳 ECS Crawler:      ❌ Failed to list tasks in cluster %s: %v",
			clusterName,
			err,
		)

		return nil, err
	}

	if len(taskArnList) == 0 {
		cnasLogger.Warn().Msgf("🐳 ECS Crawler:      📝 No running tasks found in cluster: %s", clusterName)

		return nil, err
	}

	cnasLogger.Info().Msgf("🐳 ECS Crawler:      📊 Found %d running tasks", len(taskArnList))

	// Describe tasks to get container details
	tasks, err := describeTasks(ctx, client, clusterArn, taskArnList)
	if err != nil {
		cnasLogger.Err(err).Msgf(
			"🐳 ECS Crawler:      ❌ Failed to describe tasks in cluster %s: %v",
			clusterName,
			err,
		)

		return nil, err
	}
	return tasks, nil
}

// analyzeENI analyzes a specific ENI for public exposure.
func analyzeENI(
	ctx context.Context,
	ec2Client *ec2.Client,
	eniId string,
	cnasLogger zerolog.Logger,
) (*ENIAnalysis, error) {
	analysis := &ENIAnalysis{
		SecurityGroups: []string{},
		OpenPorts:      []string{},
		PrivateIPs:     []string{},
		PublicIPs:      []string{},
	}

	// Describe the ENI
	eniResp, err := ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{eniId},
	})
	if err != nil {
		cnasLogger.Err(err).Msgf("🐳 ECS Crawler: failed to describe ENI %s", eniId)
		return analysis, fmt.Errorf("failed to describe ENI %s: %w", eniId, err)
	}

	if len(eniResp.NetworkInterfaces) == 0 {
		cnasLogger.Err(err).Msgf("🐳 ECS Crawler: ENI %s not found", eniId)
		return analysis, fmt.Errorf("ENI %s not found", eniId)
	}

	eni := eniResp.NetworkInterfaces[0]

	// Check for public IP
	if eni.Association != nil && eni.Association.PublicIp != nil {
		analysis.HasPublicIP = true
		analysis.PublicIPs = append(analysis.PublicIPs, *eni.Association.PublicIp)
	}

	// Collect private IPs
	if eni.PrivateIpAddress != nil {
		analysis.PrivateIPs = append(analysis.PrivateIPs, *eni.PrivateIpAddress)
	}

	// Check if subnet is public
	if eni.SubnetId != nil {
		isPublic, err := isSubnetPublic(ctx, ec2Client, *eni.SubnetId)
		if err != nil {
			cnasLogger.Warn().Msgf(
				"🐳 ECS Crawler: ⚠️ Warning: Failed to check if subnet %s is public: %v\n",
				*eni.SubnetId,
				err,
			)
		} else {
			analysis.IsInPublicSubnet = isPublic
		}
	}

	// Analyze security groups
	var sgIds []string
	for _, sg := range eni.Groups {
		if sg.GroupId != nil {
			sgIds = append(sgIds, *sg.GroupId)
			analysis.SecurityGroups = append(analysis.SecurityGroups, *sg.GroupId)
		}
	}

	// Analyze security group rules for open ports
	openPorts, err := analyzeSecurityGroupRules(ctx, ec2Client, sgIds)
	if err != nil {
		cnasLogger.Warn().Msgf("🐳 ECS Crawler: ⚠️ Warning: Failed to analyze security group rules: %v\n", err)
	} else {
		analysis.OpenPorts = openPorts
	}

	return analysis, nil
}

// isSubnetPublic determines if a subnet is public by checking route table.
func isSubnetPublic(ctx context.Context, ec2Client *ec2.Client, subnetId string) (bool, error) {
	// Get route tables associated with this subnet
	routeTablesResp, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("association.subnet-id"),
				Values: []string{subnetId},
			},
		},
	})
	if err != nil {
		return false, err
	}

	// Check all route tables (including main route table for VPC)
	for _, rt := range routeTablesResp.RouteTables {
		for _, route := range rt.Routes {
			// Check if there's a route to internet gateway
			if route.GatewayId != nil && aws.ToString(route.GatewayId) != "" {
				// If destination is 0.0.0.0/0 and gateway starts with "igw-", it's public
				if route.DestinationCidrBlock != nil && *route.DestinationCidrBlock == "0.0.0.0/0" {
					gatewayId := aws.ToString(route.GatewayId)
					if len(gatewayId) > 4 && gatewayId[:4] == "igw-" {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// analyzeSecurityGroupRules analyzes security group rules to find open ports.
func analyzeSecurityGroupRules(ctx context.Context, ec2Client *ec2.Client, sgIds []string) ([]string, error) {
	if len(sgIds) == 0 {
		return []string{}, nil
	}

	sgResp, err := ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIds,
	})
	if err != nil {
		return nil, err
	}

	var openPorts []string
	for _, sg := range sgResp.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			// Check if rule allows access from anywhere (0.0.0.0/0)
			for _, ipRange := range rule.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					if rule.FromPort != nil && rule.ToPort != nil {
						if *rule.FromPort == *rule.ToPort {
							openPorts = append(openPorts, strconv.Itoa(int(*rule.FromPort)))
						} else {
							openPorts = append(openPorts, fmt.Sprintf("%d-%d", *rule.FromPort, *rule.ToPort))
						}
					}
				}
			}
		}
	}

	return openPorts, nil
}

// LoadBalancerAnalysis contains load balancer exposure analysis.
type LoadBalancerAnalysis struct {
	LoadBalancers []string
}

// analyzeLoadBalancerExposure checks if task is associated with load balancers.
//func analyzeLoadBalancerExposure(
//	ctx context.Context,
//	client *elasticloadbalancingv2.Client,
//	cnasLogger zerolog.Logger,
//) (*LoadBalancerAnalysis, error) {
//	// _, err := client.DescribeLoadBalancerAttributes(ctx)
//	analysis := &LoadBalancerAnalysis{
//		LoadBalancers: []string{},
//	}
//
//	// This is a simplified check - in practice, you'd need to check target groups
//	// and correlate with task ENIs or container ports
//
//	// For now, we'll skip this complex analysis and return empty results
//	// In a full implementation, you would:
//	// 1. List all target groups
//	// 2. Check if any targets match the task's ENI IPs
//	// 3. Find load balancers associated with those target groups
//
//	cnasLogger.Warn().Msgf("🐳 ECS Crawler: ⚠️ Load balancer analysis not fully implemented - returning empty results\n")
//
//	return analysis, fmt.Errorf("Todo Analyzing load balancer exposure... \n")
//}

func describeCluster(ctx context.Context, client *ecs.Client, clusterArn string) (*types2.Cluster, error) {
	resp, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: []string{clusterArn},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Clusters) > 0 {
		return &resp.Clusters[0], nil
	}

	return nil, nil
}

func listClusterTasksArns(ctx context.Context, client *ecs.Client, clusterArn string) ([]string, error) {
	var allTaskArns []string
	var nextToken *string

	// Paginate through tasks
	for {
		input := &ecs.ListTasksInput{
			Cluster:       &clusterArn,
			DesiredStatus: types2.DesiredStatusRunning, // Only running tasks
			MaxResults:    aws.Int32(maxTasksPerPage),  // AWS maximum
			NextToken:     nextToken,
		}

		output, err := client.ListTasks(ctx, input)
		if err != nil {
			return nil, err
		}

		allTaskArns = append(allTaskArns, output.TaskArns...)

		// Check if there are more results
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allTaskArns, nil
}

func describeTasks(
	ctx context.Context,
	client *ecs.Client,
	clusterArn string,
	taskArnList []string,
) ([]types2.Task, error) {
	if len(taskArnList) == 0 {
		return nil, nil
	}

	var allTasks []types2.Task
	// Process tasks in batches of taskDescriptionBatchSize
	for i := 0; i < len(taskArnList); i += taskDescriptionBatchSize {
		end := i + taskDescriptionBatchSize
		if end > len(taskArnList) {
			end = len(taskArnList)
		}

		batch := taskArnList[i:end]
		output, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: &clusterArn,
			Tasks:   batch,
		})
		if err != nil {
			return nil, err
		}

		allTasks = append(allTasks, output.Tasks...)
	}

	return allTasks, nil
}

// createContainerData creates a ContainerData object from cluster, task, and container information
// with optional network analysis.
func createContainerData(
	cluster *types2.Cluster,
	task *types2.Task,
	container *types2.Container,
	networkAnalysis *NetworkExposureAnalysis,
	region string,
) ContainerData {

	containerData := ContainerData{
		ClusterName: aws.ToString(cluster.ClusterName),
		Name:        aws.ToString(container.Name),
		Image:       aws.ToString(container.Image),
		Status:      aws.ToString(container.LastStatus),
		RuntimeID:   aws.ToString(container.RuntimeId),
		TaskARN:     aws.ToString(task.TaskArn),
		TaskStatus:  aws.ToString(task.LastStatus),
		Region:      region,
	}

	// Network information - safely handle optional fields
	if len(container.NetworkBindings) > 0 {
		binding := container.NetworkBindings[0] // Take first binding
		if binding.HostPort != nil {
			containerData.HostPort = int(*binding.HostPort)
		}
		if binding.ContainerPort != nil {
			containerData.ContainerPort = int(*binding.ContainerPort)
		}
		if binding.Protocol != "" {
			containerData.Protocol = string(binding.Protocol)
		}
	}

	if len(container.NetworkInterfaces) > 0 {
		netInterface := container.NetworkInterfaces[0] // Take first interface
		if netInterface.PrivateIpv4Address != nil {
			containerData.PrivateIP = aws.ToString(netInterface.PrivateIpv4Address)
		}
	}

	if networkAnalysis != nil {
		containerData.PublicExposed = networkAnalysis.IsPubliclyExposed
	} else {
		// Fallback to basic exposure logic
		containerData.PublicExposed = containerData.HostPort > 0
	}

	return containerData
}

// getTaskDetails retrieves task details needed for network analysis.
func getTaskDetails(
	ctx context.Context,
	ecsClient *ecs.Client,
	clusterName, taskArn string,
) (*types2.Task, error) {
	input := &ecs.DescribeTasksInput{
		Cluster: aws.String(clusterName),
		Tasks:   []string{taskArn},
	}

	resp, err := ecsClient.DescribeTasks(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe task %s: %w", taskArn, err)
	}

	if len(resp.Tasks) == 0 {
		return nil, fmt.Errorf("task %s not found", taskArn)
	}

	return &resp.Tasks[0], nil
}

func containerToResource(containerData ContainerData) model.FlatResource {

	// Create result with UUID - use the embedded StoreResourceFlat directly
	result := model.FlatResource{
		ID: uuid.NewString(),
		StoreResourceFlat: &grpcType.StoreResourceFlat{
			Name:          containerData.Name,
			Type:          grpcType.ResourceType_CONTAINER,
			Image:         containerData.Image,
			ImageSha:      "",
			Metadata:      nil,
			PublicExposed: containerData.PublicExposed,
			Correlation:   nil,
			ClusterName:   containerData.ClusterName,
			ClusterType:   grpcType.ResourceGroupType_ECS,
			ProviderId:    containerData.TaskARN,
			Region:        containerData.Region,
		},
	}

	return result
}

func setContainerNetworkPubliclyExposed(
	containerData *ContainerData,
	containerNetworkAnalysis *NetworkExposureAnalysis,
) {
	// Enhanced public exposure determination
	var publicExposed bool
	if containerNetworkAnalysis != nil {
		publicExposed = containerNetworkAnalysis.IsPubliclyExposed
	} else {
		// Fallback to basic logic
		publicExposed = containerData.HostPort > 0
	}

	containerData.PublicExposed = publicExposed
}

func createTaskArnContainerNetworkMap(
	ctx context.Context,
	ecsClient *ecs.Client,
	ec2Client *ec2.Client,
	//elbClient *elasticloadbalancingv2.Client,
	taskArnContainerDataMap map[string]ContainerData,
	cnasLogger zerolog.Logger,
) map[string]*NetworkExposureAnalysis {
	taskArnContainerNetworkMap := make(map[string]*NetworkExposureAnalysis)
	for taskArn, container := range taskArnContainerDataMap {
		cnasLogger.Info().Msgf("🐳 ECS Crawler: 🔍 Analyzing network exposure for task: %s", taskArn)

		// Get task details for network analysis
		taskDetails, err := getTaskDetails(ctx, ecsClient, container.ClusterName, taskArn)
		if err != nil {
			cnasLogger.Info().Msgf("🐳 ECS Crawler: ⚠️ Warning: Failed to get task details for %s: %v", taskArn, err)
			continue
		}

		// Perform comprehensive network analysis
		networkAnalysis, err := analyzeNetworkExposure(ctx, ec2Client /*, elbClient*/, taskDetails, cnasLogger)
		if err != nil {
			cnasLogger.Err(err).Msgf("🐳 ECS Crawler: ⚠️ Warning: Failed to analyze network exposure for %s: %v", taskArn, err)
			// Create basic analysis as fallback
			networkAnalysis = &NetworkExposureAnalysis{
				IsPubliclyExposed: container.HostPort > 0,
				ExposureReasons:   []string{"Basic port mapping check"},
				NetworkMode:       "unknown",
				SecurityGroups:    []string{},
				OpenPorts:         []string{},
				LoadBalancers:     []string{},
				PrivateIPs:        []string{container.PrivateIP},
				PublicIPs:         []string{},
				NetworkInterfaces: []string{},
			}
		}

		taskArnContainerNetworkMap[taskArn] = networkAnalysis
	}

	return taskArnContainerNetworkMap
}

func createTaskArnContainerMap(containerData []ContainerData) map[string]ContainerData {
	taskArnContainerDataMap := make(map[string]ContainerData)
	for _, container := range containerData {
		taskArnContainerDataMap[container.TaskARN] = container
	}

	return taskArnContainerDataMap
}

// analyzeNetworkExposure performs comprehensive network exposure analysis for a task
//
//goland:noinspection SpellCheckingInspection
func analyzeNetworkExposure(
	ctx context.Context,
	ec2Client *ec2.Client,
	//elbv2Client *elasticloadbalancingv2.Client,
	task *types2.Task,
	cnasLogger zerolog.Logger,
) (*NetworkExposureAnalysis, error) {
	analysis := &NetworkExposureAnalysis{
		ExposureReasons:   []string{},
		SecurityGroups:    []string{},
		OpenPorts:         []string{},
		LoadBalancers:     []string{},
		PrivateIPs:        []string{},
		PublicIPs:         []string{},
		NetworkInterfaces: []string{},
	}

	// Analyze network configuration from task definition
	if task.TaskDefinitionArn != nil {
		// Extract network mode (awsvpc, bridge, host)
		// This would require describing the task definition, for now assume awsvpc based on ENIs
		if len(task.Attachments) > 0 {
			analysis.NetworkMode = "awsvpc"
		} else {
			analysis.NetworkMode = "bridge"
		}
	}

	// Analyze ENI attachments for awsvpc mode
	var eniIds []string
	for _, attachment := range task.Attachments {
		if attachment.Type != nil && *attachment.Type == "ElasticNetworkInterface" {
			for _, detail := range attachment.Details {
				if detail.Name != nil && *detail.Name == "networkInterfaceId" && detail.Value != nil {
					eniIds = append(eniIds, *detail.Value)
					analysis.NetworkInterfaces = append(analysis.NetworkInterfaces, *detail.Value)
				}
			}
		}
	}

	// Analyze each ENI for public exposure
	for _, eniId := range eniIds {
		eniAnalysis, err := analyzeENI(ctx, ec2Client, eniId, cnasLogger)
		if err != nil {
			cnasLogger.Err(err).Msgf("🐳 ECS Crawler: ⚠️ Warning: Failed to analyze ENI %s: %v\n", eniId, err)
			continue
		}

		// Merge ENI analysis results
		if eniAnalysis.HasPublicIP {
			analysis.HasPublicIP = true
			analysis.PublicIPs = append(analysis.PublicIPs, eniAnalysis.PublicIPs...)
			analysis.ExposureReasons = append(analysis.ExposureReasons, "Has public IP address")
		}

		if eniAnalysis.IsInPublicSubnet {
			analysis.IsInPublicSubnet = true
			analysis.ExposureReasons = append(analysis.ExposureReasons, "Running in public subnet")
		}

		analysis.PrivateIPs = append(analysis.PrivateIPs, eniAnalysis.PrivateIPs...)
		analysis.SecurityGroups = append(analysis.SecurityGroups, eniAnalysis.SecurityGroups...)
		analysis.OpenPorts = append(analysis.OpenPorts, eniAnalysis.OpenPorts...)

		if len(eniAnalysis.OpenPorts) > 0 {
			analysis.ExposureReasons = append(analysis.ExposureReasons, fmt.Sprintf("Open ports: %v", eniAnalysis.OpenPorts))
		}
	}

	// Check for load balancer associations
	//lbAnalysis, err := analyzeLoadBalancerExposure(ctx, elbv2Client, cnasLogger)
	//if err != nil {
	//	cnasLogger.Warn().Msgf("🐳 ECS Crawler: ⚠️ Warning: Failed to analyze load balancer exposure: %v\n", err)
	//} else if len(lbAnalysis.LoadBalancers) > 0 {
	//	analysis.LoadBalancers = lbAnalysis.LoadBalancers
	//	analysis.ExposureReasons = append(analysis.ExposureReasons, "Associated with load balancer")
	//}

	// todo improve this logic , one condition is enough
	// Determine overall exposure
	// Determine overall exposure - a container is publicly exposed if it meets any of these conditions:
	// 1. Has a public IP address
	// 2. Is in a public subnet AND has open ports that allow external access
	// 3. Is associated with a public load balancer
	analysis.IsPubliclyExposed = analysis.HasPublicIP ||
		(analysis.IsInPublicSubnet && len(analysis.OpenPorts) > 0) ||
		len(analysis.LoadBalancers) > 0

	return analysis, nil
}

func ecsCrawlTimer(cnasLogger zerolog.Logger) func() {
	start := time.Now()
	return func() {
		cnasLogger.Info().Msgf("🐳 ECS Crawler: ✅ Crawl took %s to complete!", time.Since(start))
	}
}
func ecsCrawlRegionTimer(cnasLogger zerolog.Logger, region string) func() {
	start := time.Now()
	return func() {
		cnasLogger.Info().Msgf("🐳 ECS Crawler: ✅ Crawl region %s took %s to complete!", region, time.Since(start))
	}
}
