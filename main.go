package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
)

// Global constant for the target role ARN
const TargetRoleArn = "arn:aws:iam::822112283600:role/CnasTargetRole"
const DEFAULT_REGION = "us-east-1" // Default region for getting all regions

type ContainerData struct {
	Cluster         string
	ContainerName   string
	Image           string
	Status          string
	RuntimeID       string
	TaskARN         string
	TaskStatus      string
	HostPort        int
	ContainerPort   int
	Protocol        string
	PrivateIP       string
	PublicExposed   bool
	NetworkMode     string
	SecurityGroups  string
	OpenPorts       string
	ExposureReasons string
	Region          string
	Timestamp       string
}

// ResourceType represents the type of the resource
type ResourceType string

const (
	ResourceTypeContainer ResourceType = "CONTAINER"
)

// ResourceGroupType represents the type of the resource group
type ResourceGroupType string

const (
	ResourceGroupTypeECS ResourceGroupType = "ECS"
)

type StoreResourceFlat struct {
	Name          string
	Type          ResourceType
	Image         string
	ImageSHA      string
	Metadata      map[string]string
	PublicExposed bool
	Correlation   string
	ClusterName   string
	ClusterType   ResourceGroupType
	ProviderID    string
	Region        string
}

//Name:          container.Name,
//Type:          resources.ResourceType_CONTAINER,
//Image:         container.Image,
//ImageSha:      container.ImageSHA,
//Metadata:      container.Tags,
//PublicExposed: isExposed,
//Correlation:   nil,
//ClusterName:   cluster.Name,
//ClusterType:   resources.ResourceGroupType_EKS,
//ProviderId:    cluster.Arn,
//Region:        cluster.Region,
//type StoreResourceFlat struct {
//	state         protoimpl.MessageState   `protogen:"open.v1"`
//	Name          string                   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`                                                                                   // Name of the resource
//	Type          ResourceType             `protobuf:"varint,2,opt,name=type,proto3,enum=resources.ResourceType" json:"type,omitempty"`                                                      // Type of the resource
//	Image         string                   `protobuf:"bytes,3,opt,name=image,proto3" json:"image,omitempty"`                                                                                 // Identified Image source for the resource
//	ImageSha      string                   `protobuf:"bytes,4,opt,name=image_sha,json=imageSha,proto3" json:"image_sha,omitempty"`                                                           // Identified Image SHA for the resource
//	Metadata      map[string]string        `protobuf:"bytes,5,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"` // Generic resource metadata
//	PublicExposed bool                     `protobuf:"varint,6,opt,name=public_exposed,json=publicExposed,proto3" json:"public_exposed,omitempty"`                                           // Indicates if resource is publicly exposed
//	Correlation   *StoreRuntimeCorrelation `protobuf:"bytes,7,opt,name=correlation,proto3" json:"correlation,omitempty"`                                                                     // Optional runtime correlation for the resource
//	ClusterName   string                   `protobuf:"bytes,8,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`                                                  // Group name
//	ClusterType   ResourceGroupType        `protobuf:"varint,9,opt,name=cluster_type,json=clusterType,proto3,enum=resources.ResourceGroupType" json:"cluster_type,omitempty"`                // Type of the resource group
//	ProviderId    string                   `protobuf:"bytes,10,opt,name=provider_id,json=providerId,proto3" json:"provider_id,omitempty"`                                                    // Cloud provider identifier
//	Region        string                   `protobuf:"bytes,11,opt,name=region,proto3" json:"region,omitempty"`                                                                              // Cloud region
//	unknownFields protoimpl.UnknownFields
//	sizeCache     protoimpl.SizeCache
//}

// FlatResourceResult represents the result structure with ID and StoreResourceFlat
type FlatResourceResult struct {
	ID                string
	StoreResourceFlat StoreResourceFlat
}

// NetworkExposureAnalysis contains detailed network exposure information
type NetworkExposureAnalysis struct {
	IsPubliclyExposed bool
	ExposureReasons   []string
	NetworkMode       string
	HasPublicIP       bool
	IsInPublicSubnet  bool
	SecurityGroups    []string
	OpenPorts         []string
	LoadBalancers     []string
	PrivateIPs        []string
	PublicIPs         []string
	NetworkInterfaces []string
}

// ENIAnalysis contains ENI-specific analysis results
type ENIAnalysis struct {
	HasPublicIP      bool
	IsInPublicSubnet bool
	SecurityGroups   []string
	OpenPorts        []string
	PrivateIPs       []string
	PublicIPs        []string
}

func main() {
	// Create a context
	ctx := context.TODO()

	defaultCfg, err := loadAWSConfig(ctx, DEFAULT_REGION)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ AWS Configuration failed for default region %s: %v", DEFAULT_REGION, err)
		fmt.Println(errorMsg)
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	defaultEC2Client := ec2.NewFromConfig(defaultCfg)
	fmt.Println("✅ EC2 Client created successfully for region discovery")

	// Get all AWS regions
	regions, err := listRegions(ctx, defaultEC2Client)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to get AWS regions: %v", err)
		fmt.Println(errorMsg)

		log.Fatalf("Unable to get AWS regions: %v", err)
	}

	fmt.Printf("🌍 Found %d regions to explore: %v\n\n", len(regions), regions)

	// Process containers from all regions
	var allFlatResources []FlatResourceResult
	totalContainers := 0

	for _, region := range regions {

		cfg, err := loadAWSConfig(ctx, region)
		if err != nil {
			fmt.Printf("⚠️ Failed to load AWS config for region %s: %v\n", region, err)
			continue
		}

		// Create clients for this region
		fmt.Printf("🔧 Creating AWS clients for region %s...\n", region)
		ecsClient := ecs.NewFromConfig(cfg)
		ec2Client := ec2.NewFromConfig(cfg)
		elbv2Client := elasticloadbalancingv2.NewFromConfig(cfg)

		// List containers in this region
		fmt.Printf("🐳 Listing ECS containers in region %s...\n", region)
		regionContainers, err := listRegionContainers(ctx, ecsClient, region)
		if err != nil {
			fmt.Printf("⚠️ ECS operation failed in region %s: %v\n", region, err)
			continue
		}

		fmt.Printf("📊 Found %d containers in region %s\n", len(regionContainers), region)
		totalContainers += len(regionContainers)

		// Perform network analysis and generate flat resources
		if len(regionContainers) > 0 {
			fmt.Printf("🔍 Analyzing network exposure for region %s...\n", region)

			// Generate flat resources for this region
			regionFlatResources, err := MapAWSToFlatResource(ctx, ecsClient, ec2Client, elbv2Client, regionContainers, region)
			if err != nil {
				fmt.Printf("⚠️ Failed to analyze containers in region %s: %v\n", region, err)
				continue
			}
			allFlatResources = append(allFlatResources, regionFlatResources...)
			fmt.Printf("✅ Successfully analyzed %d containers in region %s\n", len(regionFlatResources), region)

		} else {
			fmt.Printf("📝 No containers found in region %s\n", region)
		}
	}

	// Print detailed results after all regions are processed
	if len(allFlatResources) > 0 {
		fmt.Println("\n📋 Detailed FlatResourceResult (CSV Format):")
		fmt.Println("============================================")

		// Print CSV headers
		fmt.Println("ID,Name,Type,Image,ImageSHA,PublicExposed,Correlation,ClusterName,ClusterType,ProviderID,Region,Metadata")

		// Print each result as CSV row
		for _, result := range allFlatResources {
			// Handle metadata - convert map to key=value pairs
			metadataStr := ""
			if len(result.StoreResourceFlat.Metadata) > 0 {
				var metadataPairs []string
				for key, value := range result.StoreResourceFlat.Metadata {
					metadataPairs = append(metadataPairs, fmt.Sprintf("%s=%s", key, value))
				}
				metadataStr = fmt.Sprintf("\"%s\"", strings.Join(metadataPairs, ";"))
			}

			// Escape any commas in string fields by wrapping in quotes
			name := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Name)
			image := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Image)
			imageSHA := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.ImageSHA)
			correlation := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.Correlation)
			clusterName := fmt.Sprintf("\"%s\"", result.StoreResourceFlat.ClusterName)

			fmt.Printf("%s,%s,%s,%s,%s,%t,%s,%s,%s,%s,%s,%s\n",
				result.ID,
				name,
				result.StoreResourceFlat.Type,
				image,
				imageSHA,
				result.StoreResourceFlat.PublicExposed,
				correlation,
				clusterName,
				result.StoreResourceFlat.ClusterType,
				result.StoreResourceFlat.ProviderID,
				result.StoreResourceFlat.Region,
				metadataStr)
		}
		//return allFlatResources
	}
}

func listClientClusters(ctx context.Context, client *ecs.Client) ([]*ecsTypes.Cluster, error) {
	// Print detailed request information

	var allClusters []*ecsTypes.Cluster

	input := &ecs.ListClustersInput{
		MaxResults: &[]int32{10}[0], // List up to 10 clusters
	}

	clustersList, err := client.ListClusters(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	// Success - print results
	for i, clusterArn := range clustersList.ClusterArns {
		fmt.Printf("\n  %d. %s\n", i+1, clusterArn)

		// Describe each cluster
		fmt.Printf("     🔍 Describing cluster details...\n")

		cluster, err := DescribeCluster(client, clusterArn)
		if err != nil {
			errorMsg := fmt.Sprintf("     ❌ Failed to describe cluster %s: %v", clusterArn, err)
			fmt.Println(errorMsg)
			continue
		}

		if cluster == nil {
			noDataMsg := "     ⚠️ No cluster data returned"
			fmt.Println(noDataMsg)
			continue
		}
		allClusters = append(allClusters, cluster)

	}
	return allClusters, nil
}

func listContainersInClusters(client *ecs.Client, clusters []*ecsTypes.Cluster, region string) ([]ContainerData, error) {

	allContainers := make([]ContainerData, 0)
	for _, cluster := range clusters {
		fmt.Printf("\n🔍 Processing cluster: %s\n", aws.ToString(cluster.ClusterName))
		clusterContainer, err := listContainersInCluster(client, cluster, region)
		if err != nil {
			errorMsg := fmt.Sprintf("     ❌ Failed to list containers in cluster %s: %v", aws.ToString(cluster.ClusterName), err)
			fmt.Println(errorMsg)
			continue
		}
		allContainers = append(allContainers, clusterContainer...)
	}
	return allContainers, nil
}

func listContainersInCluster(client *ecs.Client, cluster *ecsTypes.Cluster, region string) ([]ContainerData, error) {
	clusterArn := aws.ToString(cluster.ClusterArn)
	clusterName := aws.ToString(cluster.ClusterName)
	fmt.Printf("     🔍 Listing containers in cluster: %s\n", clusterName)

	var containers []ContainerData

	// Get tasks in the cluster
	taskArns, err := listTasks(client, clusterArn)
	if err != nil {
		errorMsg := fmt.Sprintf("     ❌ Failed to list tasks in cluster %s: %v", clusterName, err)
		fmt.Println(errorMsg)

		return nil, err
	}

	if len(taskArns) == 0 {
		noTasksMsg := fmt.Sprintf("     📝 No running tasks found in cluster: %s", clusterName)
		fmt.Println(noTasksMsg)

		return containers, nil
	}

	fmt.Printf("     📊 Found %d running tasks\n", len(taskArns))

	// Describe tasks to get container details
	tasks, err := describeTasks(client, clusterArn, taskArns)
	if err != nil {
		errorMsg := fmt.Sprintf("     ❌ Failed to describe tasks in cluster %s: %v", clusterName, err)
		fmt.Println(errorMsg)

		return nil, err
	}

	// Print container details for each task
	var containerDetails []string
	totalContainers := 0

	for taskIndex, task := range tasks {
		fmt.Printf("       📋 Task %d: %s\n", taskIndex+1, aws.ToString(task.TaskArn))
		fmt.Printf("          Status: %s\n", aws.ToString(task.LastStatus))
		fmt.Printf("          Desired Status: %s\n", task.DesiredStatus)

		if task.TaskDefinitionArn != nil {
			fmt.Printf("          Task Definition: %s\n", aws.ToString(task.TaskDefinitionArn))
		}

		if len(task.Containers) == 0 {
			fmt.Printf("          ⚠️ No containers found in this task\n")
			continue
		}

		fmt.Printf("          📦 Containers (%d):\n", len(task.Containers))

		for containerIndex, container := range task.Containers {
			totalContainers++
			fmt.Printf("            %d. Container Name: %s\n", containerIndex+1, aws.ToString(container.Name))

			if container.Image != nil {
				fmt.Printf("               Image: %s\n", aws.ToString(container.Image))
			}

			fmt.Printf("               Last Status: %s\n", aws.ToString(container.LastStatus))

			if container.RuntimeId != nil {
				fmt.Printf("               Runtime ID: %s\n", aws.ToString(container.RuntimeId))
			}

			if container.TaskArn != nil {
				fmt.Printf("               Task ARN: %s\n", aws.ToString(container.TaskArn))
			}

			if len(container.NetworkBindings) > 0 {
				fmt.Printf("               Network Bindings:\n")
				for _, binding := range container.NetworkBindings {
					if binding.HostPort != nil && binding.ContainerPort != nil {
						fmt.Printf("                 - Host:%d -> Container:%d", *binding.HostPort, *binding.ContainerPort)
						if binding.Protocol != "" {
							fmt.Printf(" (%s)", binding.Protocol)
						}
						fmt.Printf("\n")
					}
				}
			}

			if len(container.NetworkInterfaces) > 0 {
				fmt.Printf("               Network Interfaces:\n")
				for _, netInterface := range container.NetworkInterfaces {
					if netInterface.PrivateIpv4Address != nil {
						fmt.Printf("                 - Private IP: %s\n", aws.ToString(netInterface.PrivateIpv4Address))
					}
				}
			}

			// Log container details
			containerDetailStr := fmt.Sprintf("Container: %s | Image: %s | Status: %s | Task: %s",
				aws.ToString(container.Name),
				aws.ToString(container.Image),
				aws.ToString(container.LastStatus),
				aws.ToString(task.TaskArn))
			containerDetails = append(containerDetails, containerDetailStr)

			// Create container data object WITHOUT adding to CSV/JSON yet
			containerData := createContainerData(cluster, &task, &container, nil, region)
			containers = append(containers, containerData)
		}
		fmt.Printf("\n")
	}

	// Summary and logging
	summaryMsg := fmt.Sprintf("Found %d containers across %d tasks in cluster %s", totalContainers, len(tasks), clusterName)
	fmt.Printf("     ✅ %s\n", summaryMsg)

	return containers, nil
}

// analyzeENI analyzes a specific ENI for public exposure
func analyzeENI(ctx context.Context, ec2Client *ec2.Client, eniId string) (*ENIAnalysis, error) {
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
		return analysis, fmt.Errorf("failed to describe ENI %s: %w", eniId, err)
	}

	if len(eniResp.NetworkInterfaces) == 0 {
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
			fmt.Printf("⚠️ Warning: Failed to check if subnet %s is public: %v\n", *eni.SubnetId, err)
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
		fmt.Printf("⚠️ Warning: Failed to analyze security group rules: %v\n", err)
	} else {
		analysis.OpenPorts = openPorts
	}

	return analysis, nil
}

// isSubnetPublic determines if a subnet is public by checking route table
func isSubnetPublic(ctx context.Context, ec2Client *ec2.Client, subnetId string) (bool, error) {
	// Get route tables associated with this subnet
	routeTablesResp, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2Types.Filter{
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

// analyzeSecurityGroupRules analyzes security group rules to find open ports
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

// LoadBalancerAnalysis contains load balancer exposure analysis
type LoadBalancerAnalysis struct {
	LoadBalancers []string
}

// analyzeLoadBalancerExposure checks if task is associated with load balancers
func analyzeLoadBalancerExposure() (*LoadBalancerAnalysis, error) {
	analysis := &LoadBalancerAnalysis{
		LoadBalancers: []string{},
	}

	// This is a simplified check - in practice, you'd need to check target groups
	// and correlate with task ENIs or container ports

	// For now, we'll skip this complex analysis
	// In a full implementation, you would:
	// 1. List all target groups
	// 2. Check if any targets match the task's ENI IPs
	// 3. Find load balancers associated with those target groups

	return analysis, nil
}

// listRegions gets all AWS regions using EC2 client
func listRegions(ctx context.Context, ec2Client *ec2.Client) ([]string, error) {
	fmt.Println("🌍 Getting all AWS regions...")

	resp, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	var regions []string
	for _, region := range resp.Regions {
		if region.RegionName != nil {
			regions = append(regions, *region.RegionName)
		}
	}

	fmt.Printf("✅ Found %d AWS regions: %v\n", len(regions), regions)
	return regions, nil
}

// configures AWS with AssumeRole for a specific region
func loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	// Load default configuration first (for initial credentials from SSO)
	fmt.Printf("📋 Step 1: Loading base SSO credentials for region %s...\n", region)
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)
	if err == nil {
		// Test if credentials work by trying to get caller identity
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ Default credentials working for region %s!\n", region)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Default credentials failed test for region %s: %v\n", region, testErr)
		}
	}

	// OPTION 2: Try target-account profile
	fmt.Printf("📋 Option 2: Trying target-account profile for region %s...\n", region)
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("target-account"),
		config.WithRegion(region),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ Target-account credentials working for region %s!\n", region)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Target-account credentials failed test for region %s: %v\n", region, testErr)
		}
	}

	// OPTION 3: Try SSO profile (original approach)
	fmt.Printf("📋 Option 3: Trying SSO profile for region %s...\n", region)
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion(region),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ SSO credentials working for region %s!\n", region)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO credentials failed test for region %s: %v\n", region, testErr)
		}
	}

	// OPTION 4: Try SSO + AssumeRole (if you get permissions fixed)
	fmt.Printf("📋 Option 4: Trying SSO + AssumeRole for region %s...\n", region)
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion(region),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, TargetRoleArn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-ecs-cnas-session"
		})

		// Test AssumeRole
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ SSO + AssumeRole working with ARN: %s for region %s\n", TargetRoleArn, region)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO + AssumeRole failed for region %s: %v\n", region, testErr)
		}
	}

	return aws.Config{}, fmt.Errorf("❌ All credential options failed for region %s. Please check your AWS configuration", region)
}

func DescribeCluster(client *ecs.Client, clusterArn string) (*ecsTypes.Cluster, error) {
	resp, err := client.DescribeClusters(context.TODO(), &ecs.DescribeClustersInput{
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

func listTasks(client *ecs.Client, clusterArn string) ([]string, error) {
	output, err := client.ListTasks(context.TODO(), &ecs.ListTasksInput{
		Cluster:       &clusterArn,
		DesiredStatus: ecsTypes.DesiredStatusRunning, // Only running tasks
	})
	if err != nil {
		return nil, err
	}
	return output.TaskArns, nil
}

func describeTasks(client *ecs.Client, clusterArn string, taskArns []string) ([]ecsTypes.Task, error) {
	if len(taskArns) == 0 {
		return nil, nil
	}

	output, err := client.DescribeTasks(context.TODO(), &ecs.DescribeTasksInput{
		Cluster: &clusterArn,
		Tasks:   taskArns,
	})
	if err != nil {
		return nil, err
	}

	return output.Tasks, nil
}

// createContainerData creates a ContainerData object from cluster, task, and container information with optional network analysis
func createContainerData(cluster *ecsTypes.Cluster, task *ecsTypes.Task, container *ecsTypes.Container, networkAnalysis *NetworkExposureAnalysis, region string) ContainerData {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	containerData := ContainerData{
		Cluster:       aws.ToString(cluster.ClusterName),
		ContainerName: aws.ToString(container.Name),
		Image:         aws.ToString(container.Image),
		Status:        aws.ToString(container.LastStatus),
		RuntimeID:     aws.ToString(container.RuntimeId),
		TaskARN:       aws.ToString(task.TaskArn),
		TaskStatus:    aws.ToString(task.LastStatus),
		Region:        region,
		Timestamp:     timestamp,
	}

	// Network information
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

	// Enhanced network analysis data
	if networkAnalysis != nil {
		containerData.PublicExposed = networkAnalysis.IsPubliclyExposed
		containerData.NetworkMode = networkAnalysis.NetworkMode
		if len(networkAnalysis.SecurityGroups) > 0 {
			containerData.SecurityGroups = fmt.Sprintf("%v", networkAnalysis.SecurityGroups)
		}
		if len(networkAnalysis.OpenPorts) > 0 {
			containerData.OpenPorts = fmt.Sprintf("%v", networkAnalysis.OpenPorts)
		}
		if len(networkAnalysis.ExposureReasons) > 0 {
			containerData.ExposureReasons = fmt.Sprintf("%v", networkAnalysis.ExposureReasons)
		}
	} else {
		// Fallback to basic exposure logic
		containerData.PublicExposed = containerData.HostPort > 0
		containerData.NetworkMode = "unknown"
	}

	return containerData
}

func listRegionContainers(ctx context.Context, client *ecs.Client, region string) ([]ContainerData, error) {

	clusters, err := listClientClusters(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to list client clusters: %w", err)
	}
	allContainers, err := listContainersInClusters(client, clusters, region)
	return allContainers, err

}

// getTaskDetails retrieves task details needed for network analysis
func getTaskDetails(ctx context.Context, ecsClient *ecs.Client, clusterName string, taskArn string) (*ecsTypes.Task, error) {
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

// MapAWSToFlatResource converts container data to FlatResourceResult array with enhanced network analysis
func MapAWSToFlatResource(ctx context.Context, ecsClient *ecs.Client, ec2Client *ec2.Client, elbv2Client *elasticloadbalancingv2.Client, containerData []ContainerData, region string) ([]FlatResourceResult, error) {
	// Use the provided container data instead of fetching again
	allContainers := containerData

	// Create result array
	var flatResourceResult []FlatResourceResult

	// Group containers by task ARN for network analysis
	taskContainers := make(map[string][]ContainerData)
	for _, container := range containerData {
		taskContainers[container.TaskARN] = append(taskContainers[container.TaskARN], container)
	}

	// Analyze each task's network exposure
	taskNetworkAnalysis := make(map[string]*NetworkExposureAnalysis)
	for taskArn, containers := range taskContainers {
		fmt.Printf("🔍 Analyzing network exposure for task: %s\n", taskArn)

		// Get task details for network analysis
		taskDetails, err := getTaskDetails(ctx, ecsClient, containers[0].Cluster, taskArn)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to get task details for %s: %v\n", taskArn, err)
			continue
		}

		// Perform comprehensive network analysis
		networkAnalysis, err := analyzeNetworkExposure(ctx, ec2Client, elbv2Client, taskDetails)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to analyze network exposure for %s: %v\n", taskArn, err)
			// Create basic analysis as fallback
			networkAnalysis = &NetworkExposureAnalysis{
				IsPubliclyExposed: len(containers) > 0 && containers[0].HostPort > 0,
				ExposureReasons:   []string{"Basic port mapping check"},
				NetworkMode:       "unknown",
				SecurityGroups:    []string{},
				OpenPorts:         []string{},
				LoadBalancers:     []string{},
				PrivateIPs:        []string{containers[0].PrivateIP},
				PublicIPs:         []string{},
				NetworkInterfaces: []string{},
			}
		}

		taskNetworkAnalysis[taskArn] = networkAnalysis
	}

	// Map each container to FlatResourceResult with enhanced network data
	for _, container := range allContainers {
		// Get network analysis for this container's task
		networkAnalysis := taskNetworkAnalysis[container.TaskARN]

		// Create enhanced metadata map
		metadata := make(map[string]string)
		metadata["task_status"] = container.TaskStatus
		metadata["timestamp"] = container.Timestamp
		if container.Protocol != "" {
			metadata["protocol"] = container.Protocol
		}
		if container.HostPort > 0 {
			metadata["host_port"] = strconv.Itoa(container.HostPort)
		}
		if container.ContainerPort > 0 {
			metadata["container_port"] = strconv.Itoa(container.ContainerPort)
		}

		// Add network analysis data to metadata
		if networkAnalysis != nil {
			metadata["network_mode"] = networkAnalysis.NetworkMode
			metadata["has_public_ip"] = strconv.FormatBool(networkAnalysis.HasPublicIP)
			metadata["is_in_public_subnet"] = strconv.FormatBool(networkAnalysis.IsInPublicSubnet)
			if len(networkAnalysis.SecurityGroups) > 0 {
				metadata["security_groups"] = fmt.Sprintf("%v", networkAnalysis.SecurityGroups)
			}
			if len(networkAnalysis.OpenPorts) > 0 {
				metadata["open_ports"] = fmt.Sprintf("%v", networkAnalysis.OpenPorts)
			}
			if len(networkAnalysis.ExposureReasons) > 0 {
				metadata["exposure_reasons"] = fmt.Sprintf("%v", networkAnalysis.ExposureReasons)
			}
			if len(networkAnalysis.NetworkInterfaces) > 0 {
				metadata["network_interfaces"] = fmt.Sprintf("%v", networkAnalysis.NetworkInterfaces)
			}
		}

		// Enhanced public exposure determination
		var publicExposed bool
		if networkAnalysis != nil {
			publicExposed = networkAnalysis.IsPubliclyExposed
		} else {
			// Fallback to basic logic
			publicExposed = container.HostPort > 0
		}

		// Create enhanced correlation string with network data
		correlationData := fmt.Sprintf("runtime_id:%s,task_arn:%s", container.RuntimeID, container.TaskARN)
		if container.PrivateIP != "" {
			correlationData += fmt.Sprintf(",private_ip:%s", container.PrivateIP)
		}
		if networkAnalysis != nil && len(networkAnalysis.PublicIPs) > 0 {
			correlationData += fmt.Sprintf(",public_ips:%v", networkAnalysis.PublicIPs)
		}

		// Create StoreResourceFlat
		storeResourceFlat := StoreResourceFlat{
			Name:          container.ContainerName,
			Type:          ResourceTypeContainer,
			Image:         container.Image,
			ImageSHA:      "", // Not available in current container data
			Metadata:      metadata,
			PublicExposed: publicExposed,
			Correlation:   correlationData,
			ClusterName:   container.Cluster,
			ClusterType:   ResourceGroupTypeECS,
			ProviderID:    "aws",
			Region:        region,
		}

		// Create result with UUID
		result := FlatResourceResult{
			ID:                uuid.NewString(),
			StoreResourceFlat: storeResourceFlat,
		}

		flatResourceResult = append(flatResourceResult, result)
	}

	// Print summary of flatResourceResult
	fmt.Printf("📄 MapAWSToFlatResource Results Summary: Generated %d flat resources\n", len(flatResourceResult))

	return flatResourceResult, nil
}

// analyzeNetworkExposure performs comprehensive network exposure analysis for a task
func analyzeNetworkExposure(ctx context.Context, ec2Client *ec2.Client, elbv2Client *elasticloadbalancingv2.Client, task *ecsTypes.Task) (*NetworkExposureAnalysis, error) {
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
		eniAnalysis, err := analyzeENI(ctx, ec2Client, eniId)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to analyze ENI %s: %v\n", eniId, err)
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
	lbAnalysis, err := analyzeLoadBalancerExposure()
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to analyze load balancer exposure: %v\n", err)
	} else if len(lbAnalysis.LoadBalancers) > 0 {
		analysis.LoadBalancers = lbAnalysis.LoadBalancers
		analysis.ExposureReasons = append(analysis.ExposureReasons, "Associated with load balancer")
	}

	// Determine overall exposure
	analysis.IsPubliclyExposed = analysis.HasPublicIP || analysis.IsInPublicSubnet || len(analysis.LoadBalancers) > 0

	return analysis, nil
}
