// Package aws provides AWS ECS crawler functionality for discovering and analyzing containers across multiple regions.
// It includes comprehensive network analysis integration to determine public exposure of ECS containers.
package aws

import (
	"context"
	"fmt"
	"time"

	"aws-ecs-project/aws/common"
	ecsnetworkaccessanalyzer "aws-ecs-project/aws/ecs_network_access_analyzer"
	ecsTypes "aws-ecs-project/aws/ecs_types"

	"github.com/rs/zerolog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	types2 "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// Configure the network analysis approach at compile time.
const networkAnalysisApproach = ecsTypes.ApproachVPC // Change to ApproachScope to use Scope analysis

func EcsCrawl(
	regions []string,
	ctx context.Context,
	accountID, tenantID string,
	cfg *aws.Config,
	cnasLogger zerolog.Logger,
) []ecsTypes.ContainerData {
	defer ecsCrawlTimer(cnasLogger)()

	// Create channels for coordination
	type regionResult struct {
		containerDataList []ecsTypes.ContainerData
		region            string
		err               error
	}

	resultChan := make(chan regionResult, len(regions))

	// Start workers for each region
	for _, region := range regions {
		go func(regionName string) {
			// Create a copy of config for this region to avoid race conditions
			regionCfg := cfg.Copy()
			regionCfg.Region = regionName

			regionContainersDataList, err := crawlRegionContainers(regionName, ctx, accountID, tenantID, regionCfg, cnasLogger)
			if err != nil {
				crawlErr := common.NewECSError(regionName, "crawl region containers", err)
				cnasLogger.Warn().Msgf("ECS Crawler: Failed to process region %s: %v", regionName, crawlErr)
				resultChan <- regionResult{nil, regionName, crawlErr}
				return
			}

			resultChan <- regionResult{regionContainersDataList, regionName, nil}
		}(region)
	}

	// Collect results
	allContainers := make([]ecsTypes.ContainerData, 0)
	for i := 0; i < len(regions); i++ {
		result := <-resultChan
		if result.err == nil {
			allContainers = append(allContainers, result.containerDataList...)
		}
	}

	cnasLogger.Info().Msgf(
		"ECS Crawler: Completed processing %d regions, found %d total containerDataList",
		len(regions),
		len(allContainers),
	)

	return allContainers
}

func crawlRegionContainers(
	regionName string,
	ctx context.Context,
	accountID,
	tenantID string,
	cfg aws.Config,
	cnasLogger zerolog.Logger,
) ([]ecsTypes.ContainerData, error) {

	defer ecsCrawlRegionTimer(cnasLogger, regionName)()

	ecsClient := createRegionClients(regionName, cfg, cnasLogger)

	// List containers in this region
	cnasLogger.Info().Msgf("ECS Crawler: Listing containers in region %s...", regionName)

	regionClustersList, err := listRegionClusters(ctx, ecsClient, cnasLogger)
	if err != nil {
		crawlErr := common.NewECSError(regionName, "list clusters", err)
		cnasLogger.Err(crawlErr).Msgf("ECS Crawler: failed to list clusters in region: %s", regionName)
		return nil, crawlErr
	}
	if regionClustersList == nil {
		cnasLogger.Info().Msgf("ECS Crawler: No clusters in region: %s.", regionName)
		return nil, nil
	}
	regionContainersDataList, err := listRegionContainersData(ctx, ecsClient, regionClustersList, regionName, cnasLogger)

	if err != nil {
		crawlErr := common.NewECSError(regionName, "list containers", err)
		cnasLogger.Err(crawlErr).Msgf("ECS Crawler: operation failed in region %s", regionName)
		return nil, crawlErr
	}

	cnasLogger.Info().Msgf(
		"ECS Crawler: Found %d containers in region %s",
		len(regionContainersDataList),
		regionName,
	)

	// Handle case when no containers found
	if len(regionContainersDataList) == 0 {
		cnasLogger.Info().Msgf("ECS Crawler: No containers found in region %s", regionName)
		return nil, nil // Not an error - region may legitimately have no containers
	}

	// Perform network analysis for all containers in this region (per-region optimization)
	if len(regionContainersDataList) > 0 {
		cnasLogger.Info().Msgf("ECS Crawler: Starting network analysis for %d containers in region %s", len(regionContainersDataList), regionName)
		err := ecsnetworkaccessanalyzer.RunAnalysis(ctx, accountID, tenantID, cfg, regionContainersDataList, networkAnalysisApproach, cnasLogger)
		if err != nil {
			cnasLogger.Warn().Msgf("ECS Crawler: Network analysis failed for region %s: %v", regionName, err)
		} else {
			cnasLogger.Info().Msgf("ECS Crawler: Network analysis completed for region %s", regionName)
		}
	}

	cnasLogger.Info().Msgf(
		"ECS Crawler: Successfully analyzed %d containers in region %s",
		len(regionContainersDataList),
		regionName,
	)

	return regionContainersDataList, nil
}

func createRegionClients(
	regionName string,
	cfg aws.Config,
	cnasLogger zerolog.Logger,
) *ecs.Client {
	// Create ECS client for this region
	cnasLogger.Info().Msgf("ECS Crawler: Creating ECS client for region %s...", regionName)
	ecsClient := ecs.NewFromConfig(cfg)

	return ecsClient
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
			MaxResults: aws.Int32(common.MaxClustersPerPage), // List up to 10 clusters
			NextToken:  nextToken,
		}

		clustersList, err := client.ListClusters(ctx, input)
		if err != nil {
			cnasLogger.Err(err).Msgf("ECS Crawler: failed to list ECS clusters")
			return nil, err
		}

		cnasLogger.Info().Msgf(
			"ECS Crawler: ECS %d clusters out of %d requested per page",
			len(clustersList.ClusterArns),
			*input.MaxResults,
		)

		// Success - print results
		for i, clusterArn := range clustersList.ClusterArns {

			// Describe each cluster
			cnasLogger.Info().Msgf(
				"ECS Crawler:      Describing cluster details:  %d). clusterArn: %s",
				i+1,
				clusterArn,
			)

			cluster, err := describeCluster(ctx, client, clusterArn)
			if err != nil {
				cnasLogger.Warn().Msgf(
					"ECS Crawler:      Failed to describe cluster %s: %v",
					clusterArn,
					err,
				)

				continue
			}

			if cluster == nil {
				cnasLogger.Warn().Msgf("ECS Crawler:      No cluster data returned")
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
) ([]ecsTypes.ContainerData, error) {

	allContainersDataList := make([]ecsTypes.ContainerData, 0)
	for _, cluster := range clusters {
		cnasLogger.Info().Msgf("ECS Crawler: Processing cluster: %s", aws.ToString(cluster.ClusterName))
		clusterContainersDataList, err := listContainersInCluster(ctx, client, cluster, region, cnasLogger)
		if err != nil {
			cnasLogger.Err(err).Msgf(
				"ECS Crawler:      Failed to list containers in cluster %s: %v",
				aws.ToString(cluster.ClusterName),
				err,
			)

			return allContainersDataList, err
		}
		allContainersDataList = append(allContainersDataList, clusterContainersDataList...)
	}

	return allContainersDataList, nil
}

func listContainersInCluster(ctx context.Context, client *ecs.Client, cluster *types2.Cluster, region string, cnasLogger zerolog.Logger) ([]ecsTypes.ContainerData, error) {
	clusterArn := aws.ToString(cluster.ClusterArn)
	clusterName := aws.ToString(cluster.ClusterName)
	cnasLogger.Info().Msgf("ECS Crawler:      Listing containersDataList in cluster: %s", clusterName)

	var containersDataList []ecsTypes.ContainerData

	// Get tasks in the cluster
	clusterTaskArnList, err := listClusterTasks(ctx, client, clusterArn)
	if err != nil {
		cnasLogger.Err(err).Msgf(
			"ECS Crawler:      Failed to list clusterTasks in cluster %s: %v",
			clusterName,
			err,
		)

		return nil, err
	}

	if len(clusterTaskArnList) == 0 {
		cnasLogger.Warn().Msgf("ECS Crawler:      No running clusterTasks found in cluster: %s", clusterName)

		return containersDataList, nil
	}

	cnasLogger.Info().Msgf("ECS Crawler:      Found %d running clusterTasks", len(clusterTaskArnList))

	// Describe tasks to get container details
	clusterTasks, err := describeClusterTasks(ctx, client, clusterArn, clusterTaskArnList)
	if err != nil {
		cnasLogger.Err(err).Msgf(
			"ECS Crawler:      Failed to describe clusterTasks in cluster %s: %v",
			clusterName,
			err,
		)

		return nil, err
	}

	totalContainers := 0

	for taskIndex, task := range clusterTasks {
		cnasLogger.Info().Msgf("ECS Crawler:           Task %d: %s", taskIndex+1, aws.ToString(task.TaskArn))

		if len(task.Containers) == 0 {
			cnasLogger.Info().Msgf("ECS Crawler:           No containersDataList found in this task")
			continue
		}

		cnasLogger.Info().Msgf("ECS Crawler:           List Containers (%d):", len(task.Containers))

		for containerIndex, container := range task.Containers {
			// Set region for each container
			totalContainers++
			cnasLogger.Info().Msgf(
				"ECS Crawler:             %d. Container Name: %s",
				containerIndex+1,
				aws.ToString(container.Name),
			)

			containerData := createContainerData(cluster, &task, &container, region)

			containersDataList = append(containersDataList, containerData)
		}
	}

	// Summary and logging
	cnasLogger.Info().Msgf(
		"ECS Crawler:      Found %d containersDataList across %d clusterTasks in cluster %s",
		totalContainers,
		len(clusterTasks),
		clusterName,
	)

	return containersDataList, nil
}

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

	return nil, fmt.Errorf("cluster %s not found", clusterArn)
}

func listClusterTasks(ctx context.Context, client *ecs.Client, clusterArn string) ([]string, error) {
	var allTaskArns []string
	var nextToken *string

	// Paginate through tasks
	for {
		input := &ecs.ListTasksInput{
			Cluster:       &clusterArn,
			DesiredStatus: types2.DesiredStatusRunning,       // Only running tasks
			MaxResults:    aws.Int32(common.MaxTasksPerPage), // AWS maximum
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

func describeClusterTasks(
	ctx context.Context,
	client *ecs.Client,
	clusterArn string,
	clusterTaskArnList []string,
) ([]types2.Task, error) {
	if len(clusterTaskArnList) == 0 {
		return nil, nil
	}

	var allTasks []types2.Task
	// Process tasks in batches of TaskDescriptionBatchSize.
	for i := 0; i < len(clusterTaskArnList); i += common.TaskDescriptionBatchSize {
		end := i + common.TaskDescriptionBatchSize
		if end > len(clusterTaskArnList) {
			end = len(clusterTaskArnList)
		}

		batch := clusterTaskArnList[i:end]
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

// createContainerData creates a ContainerData object from cluster, task, and container information.
func createContainerData(
	cluster *types2.Cluster,
	task *types2.Task,
	container *types2.Container,
	region string,
) ecsTypes.ContainerData {

	containerData := ecsTypes.ContainerData{
		ClusterName:   aws.ToString(cluster.ClusterName),
		Name:          aws.ToString(container.Name),
		Image:         aws.ToString(container.Image),
		ImageSHA:      aws.ToString(container.ImageDigest),
		TaskARN:       aws.ToString(task.TaskArn),
		Region:        region,
		NicID:         getTaskNetworkInterface(task), // Extract network interface ID
		PublicExposed: false,
	}

	return containerData
}

func ecsCrawlTimer(cnasLogger zerolog.Logger) func() {
	start := time.Now()
	return func() {
		cnasLogger.Info().Msgf("ECS Crawler: Crawl took %s to complete!", time.Since(start))
	}
}
func ecsCrawlRegionTimer(cnasLogger zerolog.Logger, region string) func() {
	start := time.Now()
	return func() {
		cnasLogger.Info().Msgf("ECS Crawler: Crawl region %s took %s to complete!", region, time.Since(start))
	}
}

// getTaskNetworkInterface extracts the network interface ID from a task.
func getTaskNetworkInterface(task *types2.Task) string {
	for _, attachment := range task.Attachments {
		if aws.ToString(attachment.Type) == "ElasticNetworkInterface" {
			for _, detail := range attachment.Details {
				if aws.ToString(detail.Name) == "networkInterfaceId" {
					return aws.ToString(detail.Value)
				}
			}
		}
	}

	return ""
}
