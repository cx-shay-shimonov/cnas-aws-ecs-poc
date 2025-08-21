package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	types2 "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type ContainerData struct {
	Name          string
	Image         string
	ImageSHA      string
	PublicExposed bool
	ClusterName   string

	TaskARN string
	Region  string
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

func EcsCrawl(
	regions []string,
	ctx context.Context,
	cfg *aws.Config,
	cnasLogger zerolog.Logger,
) []ContainerData {
	defer ecsCrawlTimer(cnasLogger)()

	// Create channels for coordination
	type regionResult struct {
		containerDataList []ContainerData
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

			regionContainersDataList, err := crawlRegionContainers(regionName, ctx, regionCfg, cnasLogger)
			if err != nil {
				cnasLogger.Warn().Msgf("ECS Crawler: Failed to process region %s: %v", regionName, err)
				resultChan <- regionResult{nil, regionName, err}

				return
			}

			resultChan <- regionResult{regionContainersDataList, regionName, nil}
		}(region)
	}

	// Collect results
	allContainers := make([]ContainerData, 0)
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
	cfg aws.Config,
	cnasLogger zerolog.Logger,
) ([]ContainerData, error) {

	defer ecsCrawlRegionTimer(cnasLogger, regionName)()

	ecsClient := createRegionClients(regionName, cfg, cnasLogger)

	// List containers in this region
	cnasLogger.Info().Msgf("ECS Crawler: Listing containers in region %s...", regionName)

	regionClustersList, err := listRegionClusters(ctx, ecsClient, cnasLogger)
	if err != nil {
		cnasLogger.Err(err).Msgf("ECS Crawler: failed to list client in region: %s.", regionName)
		return nil, err
	}
	if regionClustersList == nil {
		cnasLogger.Info().Msgf("ECS Crawler: No clusters in region: %s.", regionName)
		return nil, nil
	}
	regionContainersDataList, err := listRegionContainersData(ctx, ecsClient, regionClustersList, regionName, cnasLogger)

	if err != nil {
		cnasLogger.Err(err).Msgf("ECS Crawler: operation failed in region %s: %v", regionName, err)
		return nil, err
	}

	cnasLogger.Info().Msgf(
		"ECS Crawler: Found %d containers in region %s",
		len(regionContainersDataList),
		regionName,
	)

	// Handle case when no containers found
	if len(regionContainersDataList) == 0 {
		cnasLogger.Warn().Msgf("ECS Crawler: No containers found in region %s", regionName)
		return nil, fmt.Errorf("no containers found in region %s", regionName)
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
) (ecsClient *ecs.Client) {
	// Create clients for this region
	cnasLogger.Info().Msgf("ECS Crawler: Creating AWS clients for region %s...", regionName)
	ecsClient = ecs.NewFromConfig(cfg)

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
			MaxResults: aws.Int32(maxClustersPerPage), // List up to 10 clusters
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
) ([]ContainerData, error) {

	allContainersDataList := make([]ContainerData, 0)
	// todo use a map to avoid duplicates not implemented yet
	clusterTaskArnsPublicExposedMap := make(map[string]map[string]bool)
	for _, cluster := range clusters {
		cnasLogger.Info().Msgf("ECS Crawler: Processing cluster: %s", aws.ToString(cluster.ClusterName))
		clusterContainersDataList, err := listContainersInCluster(ctx, client, cluster, clusterTaskArnsPublicExposedMap, region, cnasLogger)
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
	cnasLogger.Info().Msgf("ECS Crawler: found total %d clusters arns groups", len(clusterTaskArnsPublicExposedMap))
	return allContainersDataList, nil
}

func listContainersInCluster(
	ctx context.Context,
	client *ecs.Client,
	cluster *types2.Cluster,
	clusterTaskArnsPublicExposedMap map[string]map[string]bool,
	region string,

	cnasLogger zerolog.Logger,
) ([]ContainerData, error) {
	clusterArn := aws.ToString(cluster.ClusterArn)
	clusterName := aws.ToString(cluster.ClusterName)
	cnasLogger.Info().Msgf("ECS Crawler:      Listing containersDataList in cluster: %s", clusterName)

	var containersDataList []ContainerData

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

			if clusterTaskArnsPublicExposedMap[clusterName] == nil {
				clusterTaskArnsPublicExposedMap[clusterName] = make(map[string]bool)
			}
			clusterTaskArnsPublicExposedMap[clusterName][containerData.TaskARN] = false

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
	// Process tasks in batches of taskDescriptionBatchSize
	for i := 0; i < len(clusterTaskArnList); i += taskDescriptionBatchSize {
		end := i + taskDescriptionBatchSize
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
) ContainerData {

	containerData := ContainerData{
		ClusterName: aws.ToString(cluster.ClusterName),
		Name:        aws.ToString(container.Name),
		Image:       aws.ToString(container.Image),
		ImageSHA:    aws.ToString(container.ImageDigest),
		TaskARN:     aws.ToString(task.TaskArn),
		Region:      region,
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
