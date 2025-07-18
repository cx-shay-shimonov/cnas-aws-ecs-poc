package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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

// Global variables for logging
var operationLogs []string
var csvData [][]string
var jsonContainers []ContainerData

// ContainerData represents a container with its cluster context for JSON export
type ContainerData struct {
	Cluster         string `json:"cluster"`
	ContainerName   string `json:"container_name"`
	Image           string `json:"image"`
	Status          string `json:"status"`
	RuntimeID       string `json:"runtime_id,omitempty"`
	TaskARN         string `json:"task_arn"`
	TaskStatus      string `json:"task_status"`
	HostPort        int    `json:"host_port,omitempty"`
	ContainerPort   int    `json:"container_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	PrivateIP       string `json:"private_ip,omitempty"`
	PublicExposed   bool   `json:"public_exposed"`
	NetworkMode     string `json:"network_mode,omitempty"`
	SecurityGroups  string `json:"security_groups,omitempty"`
	OpenPorts       string `json:"open_ports,omitempty"`
	ExposureReasons string `json:"exposure_reasons,omitempty"`
	Region          string `json:"region"`
	Timestamp       string `json:"timestamp"`
}

// ResourceType represents the type of the resource
type ResourceType string

const (
	ResourceTypeContainer ResourceType = "CONTAINER"
	ResourceTypeService   ResourceType = "SERVICE"
	ResourceTypeTask      ResourceType = "TASK"
)

// ResourceGroupType represents the type of the resource group
type ResourceGroupType string

const (
	ResourceGroupTypeECS ResourceGroupType = "ECS"
	ResourceGroupTypeEKS ResourceGroupType = "EKS"
	ResourceGroupTypeEC2 ResourceGroupType = "EC2"
)

// StoreRuntimeCorrelation represents runtime correlation for the resource
//type StoreRuntimeCorrelation struct {
//	RuntimeID   string            `json:"runtime_id,omitempty"`
//	TaskARN     string            `json:"task_arn,omitempty"`
//	NetworkInfo map[string]string `json:"network_info,omitempty"`
//}

// StoreResourceFlat represents the flattened resource structure
type StoreResourceFlat struct {
	Name          string            `json:"name"`
	Type          ResourceType      `json:"type"`
	Image         string            `json:"image"`
	ImageSHA      string            `json:"image_sha"`
	Metadata      map[string]string `json:"metadata"`
	PublicExposed bool              `json:"public_exposed"`
	Correlation   string            `json:"correlation"`
	ClusterName   string            `json:"cluster_name"`
	ClusterType   ResourceGroupType `json:"cluster_type"`
	ProviderID    string            `json:"provider_id"`
	Region        string            `json:"region"`
}

// FlatResourceResult represents the result structure with ID and StoreResourceFlat
type FlatResourceResult struct {
	ID                string            `json:"id"`
	StoreResourceFlat StoreResourceFlat `json:"store_resource_flat"`
}

// NetworkExposureAnalysis contains detailed network exposure information
type NetworkExposureAnalysis struct {
	IsPubliclyExposed bool     `json:"is_publicly_exposed"`
	ExposureReasons   []string `json:"exposure_reasons"`
	NetworkMode       string   `json:"network_mode"`
	HasPublicIP       bool     `json:"has_public_ip"`
	IsInPublicSubnet  bool     `json:"is_in_public_subnet"`
	SecurityGroups    []string `json:"security_groups"`
	OpenPorts         []string `json:"open_ports"`
	LoadBalancers     []string `json:"load_balancers"`
	PrivateIPs        []string `json:"private_ips"`
	PublicIPs         []string `json:"public_ips"`
	NetworkInterfaces []string `json:"network_interfaces"`
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
	lbAnalysis, err := analyzeLoadBalancerExposure(ctx, elbv2Client, task)
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

// ENIAnalysis contains ENI-specific analysis results
type ENIAnalysis struct {
	HasPublicIP      bool     `json:"has_public_ip"`
	IsInPublicSubnet bool     `json:"is_in_public_subnet"`
	SecurityGroups   []string `json:"security_groups"`
	OpenPorts        []string `json:"open_ports"`
	PrivateIPs       []string `json:"private_ips"`
	PublicIPs        []string `json:"public_ips"`
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
	LoadBalancers []string `json:"load_balancers"`
}

// analyzeLoadBalancerExposure checks if task is associated with load balancers
func analyzeLoadBalancerExposure(ctx context.Context, elbv2Client *elasticloadbalancingv2.Client, task *ecsTypes.Task) (*LoadBalancerAnalysis, error) {
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

// getAllRegions gets all AWS regions using EC2 client
func getAllRegions(ctx context.Context, ec2Client *ec2.Client) ([]string, error) {
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
	logToFile("Get All Regions", "ec2.Client.DescribeRegions()", "SUCCESS", fmt.Sprintf("Found %d regions", len(regions)))
	return regions, nil
}

// logToFile logs operation details to the global log slice
func logToFile(requestName, sdkFunction, status, details string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s | %s | %s | %s",
		timestamp, status, requestName, sdkFunction, details)
	operationLogs = append(operationLogs, logEntry)
}

// initializeCSV initializes the CSV data with headers
func initializeCSV() {
	headers := []string{
		"Cluster",
		"Container_Name",
		"Image",
		"Status",
		"Runtime_ID",
		"Task_ARN",
		"Task_Status",
		"Host_Port",
		"Container_Port",
		"Protocol",
		"Private_IP",
		"Public_Exposed",
		"Network_Mode",
		"Security_Groups",
		"Open_Ports",
		"Exposure_Reasons",
		"Region",
		"Timestamp",
	}
	csvData = append(csvData, headers)
}

// addContainerToCSV adds container data with cluster context and network analysis to CSV
func addContainerToCSV(cluster *ecsTypes.Cluster, task *ecsTypes.Task, container *ecsTypes.Container, networkAnalysis *NetworkExposureAnalysis, region string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Extract network information
	hostPort := ""
	containerPort := ""
	protocol := ""
	privateIP := ""

	if len(container.NetworkBindings) > 0 {
		binding := container.NetworkBindings[0] // Take first binding
		if binding.HostPort != nil {
			hostPort = strconv.Itoa(int(*binding.HostPort))
		}
		if binding.ContainerPort != nil {
			containerPort = strconv.Itoa(int(*binding.ContainerPort))
		}
		if binding.Protocol != "" {
			protocol = string(binding.Protocol)
		}
	}

	if len(container.NetworkInterfaces) > 0 {
		netInterface := container.NetworkInterfaces[0] // Take first interface
		if netInterface.PrivateIpv4Address != nil {
			privateIP = aws.ToString(netInterface.PrivateIpv4Address)
		}
	}

	// Extract network analysis data
	publicExposed := "false"
	networkMode := "unknown"
	securityGroups := ""
	openPorts := ""
	exposureReasons := ""

	if networkAnalysis != nil {
		publicExposed = strconv.FormatBool(networkAnalysis.IsPubliclyExposed)
		networkMode = networkAnalysis.NetworkMode
		if len(networkAnalysis.SecurityGroups) > 0 {
			securityGroups = fmt.Sprintf("%v", networkAnalysis.SecurityGroups)
		}
		if len(networkAnalysis.OpenPorts) > 0 {
			openPorts = fmt.Sprintf("%v", networkAnalysis.OpenPorts)
		}
		if len(networkAnalysis.ExposureReasons) > 0 {
			exposureReasons = fmt.Sprintf("%v", networkAnalysis.ExposureReasons)
		}
	} else {
		// Fallback to basic exposure logic
		if hostPort != "" && hostPort != "0" {
			publicExposed = "true"
			exposureReasons = "[Basic port mapping check]"
		}
	}

	row := []string{
		aws.ToString(cluster.ClusterName),
		aws.ToString(container.Name),
		aws.ToString(container.Image),
		aws.ToString(container.LastStatus),
		aws.ToString(container.RuntimeId),
		aws.ToString(task.TaskArn),
		aws.ToString(task.LastStatus),
		hostPort,
		containerPort,
		protocol,
		privateIP,
		publicExposed,
		networkMode,
		securityGroups,
		openPorts,
		exposureReasons,
		region,
		timestamp,
	}

	csvData = append(csvData, row)
}

// writeCSVToFile writes the CSV data to a file
func writeCSVToFile() error {
	fmt.Println("🔍 Request: Write Container Data to CSV")
	fmt.Println("📞 SDK Function: csv.NewWriter() + writer.WriteAll()")
	fmt.Println("⏳ Writing container data to containers.csv...")

	file, err := os.Create("containers.csv")
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to create CSV file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write CSV File", "os.Create()", "ERROR", errorMsg)
		return err
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			errorMsg := fmt.Sprintf("❌ Error closing CSV file: %v", closeErr)
			fmt.Println(errorMsg)
			logToFile("Write CSV File", "file.Close()", "ERROR", errorMsg)
		}
	}()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	err = writer.WriteAll(csvData)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to write CSV data: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write CSV File", "csv.Writer.WriteAll()", "ERROR", errorMsg)
		return err
	}

	// Force write to disk
	if err := file.Sync(); err != nil {
		errorMsg := fmt.Sprintf("⚠️ Warning: Failed to sync CSV file to disk: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write CSV File", "file.Sync()", "WARNING", errorMsg)
	}

	successMsg := fmt.Sprintf("✅ Container data written to containers.csv (%d rows including header)", len(csvData))
	fmt.Println(successMsg)
	logToFile("Write CSV File", "writeCSVToFile()", "SUCCESS",
		fmt.Sprintf("Written %d container records to CSV", len(csvData)-1))

	return nil
}

// addContainerToJSON adds container data with cluster context and optional network analysis to JSON array
func addContainerToJSON(cluster *ecsTypes.Cluster, task *ecsTypes.Task, container *ecsTypes.Container, networkAnalysis *NetworkExposureAnalysis, region string) {
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

	jsonContainers = append(jsonContainers, containerData)
}

// writeJSONToFile writes the container data to a JSON file
func writeJSONToFile() error {
	fmt.Println("🔍 Request: Write Container Data to JSON")
	fmt.Println("📞 SDK Function: json.MarshalIndent() + os.WriteFile()")
	fmt.Println("⏳ Writing container data to containers.json...")

	// Marshal containers array to JSON with indentation
	jsonData, err := json.MarshalIndent(jsonContainers, "", "  ")
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to marshal JSON data: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write JSON File", "json.MarshalIndent()", "ERROR", errorMsg)
		return err
	}

	// Write to file
	err = os.WriteFile("containers.json", jsonData, 0644)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to write JSON file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write JSON File", "os.WriteFile()", "ERROR", errorMsg)
		return err
	}

	successMsg := fmt.Sprintf("✅ Container data written to containers.json (%d containers)", len(jsonContainers))
	fmt.Println(successMsg)
	logToFile("Write JSON File", "writeJSONToFile()", "SUCCESS",
		fmt.Sprintf("Written %d container records to JSON", len(jsonContainers)))

	return nil
}

func main() {
	// Create a context
	ctx := context.TODO()

	// Clear any existing data and initialize fresh CSV/JSON structures
	operationLogs = []string{}
	csvData = [][]string{}
	jsonContainers = []ContainerData{}

	// Initialize CSV data structure
	initializeCSV()
	fmt.Println("📊 CSV data structure initialized")

	// Load AWS configuration for default region to discover all regions
	fmt.Println("🔍 Request: Load AWS Configuration for region discovery")
	fmt.Println("📞 SDK Function: loadAWSConfig() -> AssumeRole")
	fmt.Println("⏳ Loading AWS configuration...")

	defaultCfg, err := loadAWSConfig(ctx, DEFAULT_REGION)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ AWS Configuration failed for default region %s: %v", DEFAULT_REGION, err)
		fmt.Println(errorMsg)
		logToFile("Load AWS Configuration", "loadAWSConfig()", "ERROR", errorMsg)
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	// Log successful configuration
	configMsg := "✅ AWS Configuration loaded successfully for region discovery"
	fmt.Println(configMsg)
	logToFile("Load AWS Configuration", "loadAWSConfig()", "SUCCESS", fmt.Sprintf("AWS Configuration loaded with AssumeRole: %s", TargetRoleArn))

	// Create EC2 client to get all regions
	fmt.Println("\n🔍 Request: Create EC2 Client for region discovery")
	fmt.Println("📞 SDK Function: ec2.NewFromConfig()")
	defaultEC2Client := ec2.NewFromConfig(defaultCfg)
	fmt.Println("✅ EC2 Client created successfully for region discovery")
	logToFile("Create EC2 Client", "ec2.NewFromConfig()", "SUCCESS", "EC2 client initialized for region discovery")

	// Get all AWS regions
	regions, err := getAllRegions(ctx, defaultEC2Client)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to get AWS regions: %v", err)
		fmt.Println(errorMsg)
		logToFile("Get All Regions", "getAllRegions()", "ERROR", errorMsg)
		log.Fatalf("Unable to get AWS regions: %v", err)
	}

	fmt.Printf("🌍 Found %d regions to explore: %v\n\n", len(regions), regions)

	// Process containers from all regions
	var allFlatResources []FlatResourceResult
	totalContainers := 0

	for i, region := range regions {
		fmt.Printf("\n🌐 REGION %d/%d: %s\n", i+1, len(regions), region)
		fmt.Println("==================================================")

		// Load configuration for this specific region
		fmt.Printf("🔧 Loading AWS configuration for region %s...\n", region)
		cfg, err := loadAWSConfig(ctx, region)
		if err != nil {
			fmt.Printf("⚠️ Failed to load AWS config for region %s: %v\n", region, err)
			logToFile("Load AWS Configuration", "loadAWSConfig()", "ERROR", fmt.Sprintf("Failed for region %s: %v", region, err))
			continue
		}

		// Create clients for this region
		fmt.Printf("🔧 Creating AWS clients for region %s...\n", region)
		ecsClient := ecs.NewFromConfig(cfg)
		ec2Client := ec2.NewFromConfig(cfg)
		elbv2Client := elasticloadbalancingv2.NewFromConfig(cfg)

		// List containers in this region (without adding to CSV/JSON yet)
		fmt.Printf("🐳 Listing ECS containers in region %s...\n", region)
		regionContainers, err := listECSContainersByClusters(ctx, ecsClient, region)
		if err != nil {
			fmt.Printf("⚠️ ECS operation failed in region %s: %v\n", region, err)
			logToFile("List ECS Containers", "listECSContainersByClusters()", "ERROR", fmt.Sprintf("Failed for region %s: %v", region, err))
			continue
		}

		fmt.Printf("📊 Found %d containers in region %s\n", len(regionContainers), region)
		totalContainers += len(regionContainers)

		// Perform network analysis and generate flat resources
		if len(regionContainers) > 0 {
			fmt.Printf("🔍 Analyzing network exposure for region %s...\n", region)

			// Group containers by task ARN for network analysis
			taskContainers := make(map[string][]ContainerData)
			for _, container := range regionContainers {
				taskContainers[container.TaskARN] = append(taskContainers[container.TaskARN], container)
			}

			// Perform network analysis for each task
			taskNetworkAnalysis := make(map[string]*NetworkExposureAnalysis)
			for taskArn, containers := range taskContainers {
				fmt.Printf("   🔍 Analyzing network exposure for task: %s\n", taskArn)

				// Get task details for network analysis
				taskDetails, err := getTaskDetails(ctx, ecsClient, containers[0].Cluster, taskArn)
				if err != nil {
					fmt.Printf("   ⚠️ Warning: Failed to get task details for %s: %v\n", taskArn, err)
					// Create basic analysis as fallback
					taskNetworkAnalysis[taskArn] = &NetworkExposureAnalysis{
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
					continue
				}

				// Perform comprehensive network analysis
				networkAnalysis, err := analyzeNetworkExposure(ctx, ec2Client, elbv2Client, taskDetails)
				if err != nil {
					fmt.Printf("   ⚠️ Warning: Failed to analyze network exposure for %s: %v\n", taskArn, err)
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

				// Print network analysis results
				fmt.Printf("      📊 Network Analysis Results:\n")
				fmt.Printf("         🔐 Publicly Exposed: %v\n", networkAnalysis.IsPubliclyExposed)
				fmt.Printf("         🌐 Network Mode: %s\n", networkAnalysis.NetworkMode)
				fmt.Printf("         🏠 Private IPs: %v\n", networkAnalysis.PrivateIPs)
				if len(networkAnalysis.PublicIPs) > 0 {
					fmt.Printf("         🌍 Public IPs: %v\n", networkAnalysis.PublicIPs)
				}
				if len(networkAnalysis.SecurityGroups) > 0 {
					fmt.Printf("         🛡️ Security Groups: %v\n", networkAnalysis.SecurityGroups)
				}
				if len(networkAnalysis.OpenPorts) > 0 {
					fmt.Printf("         🚪 Open Ports: %v\n", networkAnalysis.OpenPorts)
				}
				if len(networkAnalysis.ExposureReasons) > 0 {
					fmt.Printf("         📋 Exposure Reasons: %v\n", networkAnalysis.ExposureReasons)
				}
			}

			// Now add containers to CSV and JSON with network analysis
			fmt.Printf("📝 Adding containers to output files with network analysis...\n")
			for _, container := range regionContainers {
				networkAnalysis := taskNetworkAnalysis[container.TaskARN]

				// Create enhanced container data and add to JSON
				enhancedContainer := createContainerData(&ecsTypes.Cluster{ClusterName: &container.Cluster}, &ecsTypes.Task{TaskArn: &container.TaskARN, LastStatus: &container.TaskStatus}, &ecsTypes.Container{
					Name:       &container.ContainerName,
					Image:      &container.Image,
					LastStatus: &container.Status,
					RuntimeId:  &container.RuntimeID,
				}, networkAnalysis, region)

				// Add to JSON containers
				jsonContainers = append(jsonContainers, enhancedContainer)

				// Add to CSV (we need to reconstruct the ECS objects for the CSV function)
				cluster := &ecsTypes.Cluster{ClusterName: &container.Cluster}
				task := &ecsTypes.Task{TaskArn: &container.TaskARN, LastStatus: &container.TaskStatus}
				containerObj := &ecsTypes.Container{
					Name:       &container.ContainerName,
					Image:      &container.Image,
					LastStatus: &container.Status,
					RuntimeId:  &container.RuntimeID,
				}

				// Add network bindings if available
				if container.HostPort > 0 || container.ContainerPort > 0 {
					binding := ecsTypes.NetworkBinding{}
					if container.HostPort > 0 {
						hostPort := int32(container.HostPort)
						binding.HostPort = &hostPort
					}
					if container.ContainerPort > 0 {
						containerPort := int32(container.ContainerPort)
						binding.ContainerPort = &containerPort
					}
					if container.Protocol != "" {
						binding.Protocol = ecsTypes.TransportProtocol(container.Protocol)
					}
					containerObj.NetworkBindings = []ecsTypes.NetworkBinding{binding}
				}

				// Add network interfaces if available
				if container.PrivateIP != "" {
					netInterface := ecsTypes.NetworkInterface{
						PrivateIpv4Address: &container.PrivateIP,
					}
					containerObj.NetworkInterfaces = []ecsTypes.NetworkInterface{netInterface}
				}

				addContainerToCSV(cluster, task, containerObj, networkAnalysis, region)
			}

			// Generate flat resources for this region
			regionFlatResources, err := MapAWSToFlatResource(ctx, ecsClient, ec2Client, elbv2Client, regionContainers, region)
			if err != nil {
				fmt.Printf("⚠️ Failed to analyze containers in region %s: %v\n", region, err)
				logToFile("MapAWSToFlatResource", "MapAWSToFlatResource()", "ERROR", fmt.Sprintf("Failed for region %s: %v", region, err))
			} else {
				allFlatResources = append(allFlatResources, regionFlatResources...)
				fmt.Printf("✅ Successfully analyzed %d containers in region %s\n", len(regionFlatResources), region)
			}
		} else {
			fmt.Printf("📝 No containers found in region %s\n", region)
		}
	}

	// Summary
	fmt.Printf("\n🎉 MULTI-REGION ANALYSIS COMPLETE\n")
	fmt.Printf("==================================================\n")
	fmt.Printf("📊 Regions analyzed: %d\n", len(regions))
	fmt.Printf("📦 Total containers found: %d\n", totalContainers)
	fmt.Printf("🔍 Total flat resources generated: %d\n", len(allFlatResources))

	// Log the results as JSON string
	if len(allFlatResources) > 0 {
		resultsJSON, err := json.MarshalIndent(allFlatResources, "", "  ")
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to marshal results to JSON: %v\n", err)
			logToFile("MapAWSToFlatResource", "json.MarshalIndent()", "ERROR", fmt.Sprintf("Failed to marshal results: %v", err))
		} else {
			fmt.Printf("📄 Multi-Region FlatResource Results (JSON):\n%s\n", string(resultsJSON))
			logToFile("MapAWSToFlatResource", "json.MarshalIndent()", "SUCCESS", fmt.Sprintf("Mapped %d containers to FlatResourceResult across %d regions", len(allFlatResources), len(regions)))
		}
	}

	// Write container data to CSV file
	fmt.Println("\n==================================================")
	if err := writeCSVToFile(); err != nil {
		fmt.Printf("⚠️ CSV export failed: %v\n", err)
	}

	// Write container data to JSON file
	fmt.Println("\n==================================================")
	if err := writeJSONToFile(); err != nil {
		fmt.Printf("⚠️ JSON export failed: %v\n", err)
	}

	fmt.Printf("\n🎉 Multi-region AWS ECS analysis completed successfully!\n")
	fmt.Printf("📊 Analyzed %d regions and found %d containers total\n", len(regions), totalContainers)
}

// loadAWSConfig configures AWS with AssumeRole for a specific region
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
		logToFile("List Tasks", "ecs.Client.ListTasks()", "ERROR", errorMsg)
		return nil, err
	}

	if len(taskArns) == 0 {
		noTasksMsg := fmt.Sprintf("     📝 No running tasks found in cluster: %s", clusterName)
		fmt.Println(noTasksMsg)
		logToFile("List Tasks", "ecs.Client.ListTasks()", "INFO", noTasksMsg)
		return containers, nil
	}

	fmt.Printf("     📊 Found %d running tasks\n", len(taskArns))
	logToFile("List Tasks", "ecs.Client.ListTasks()", "SUCCESS", fmt.Sprintf("Found %d tasks in cluster %s", len(taskArns), clusterName))

	// Describe tasks to get container details
	tasks, err := describeTasks(client, clusterArn, taskArns)
	if err != nil {
		errorMsg := fmt.Sprintf("     ❌ Failed to describe tasks in cluster %s: %v", clusterName, err)
		fmt.Println(errorMsg)
		logToFile("Describe Tasks", "ecs.Client.DescribeTasks()", "ERROR", errorMsg)
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
	logToFile("List Containers", "listContainersInCluster()", "SUCCESS", summaryMsg)

	// Log detailed container information
	if len(containerDetails) > 0 {
		for _, detail := range containerDetails {
			logToFile("Container Details", "ecs.Container", "INFO", detail)
		}
	}

	return containers, nil
}

func listECSContainersByClusters(ctx context.Context, client *ecs.Client, region string) ([]ContainerData, error) {
	// Print detailed request information
	requestName := "List ECS Containers Across All Clusters"
	sdkFunction := "ecs.Client.ListClusters() + listContainersInCluster()"

	fmt.Printf("🔍 Request: %s\n", requestName)
	fmt.Printf("📞 SDK Function: %s\n", sdkFunction)
	fmt.Println("⏳ Executing request...")

	var allContainers []ContainerData

	input := &ecs.ListClustersInput{
		MaxResults: &[]int32{10}[0], // List up to 10 clusters
	}

	clustersList, err := client.ListClusters(ctx, input)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ %s failed: %v", requestName, err)
		fmt.Println(errorMsg)

		// Log to output file
		logToFile(requestName, sdkFunction, "ERROR", errorMsg)

		return nil, fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	// Success - print results
	resultMsg := fmt.Sprintf("✅ %s completed successfully", requestName)
	fmt.Println(resultMsg)
	fmt.Printf("📊 Found %d ECS clusters:\n", len(clustersList.ClusterArns))

	var listClustersOutput []string
	for i, clusterArn := range clustersList.ClusterArns {
		fmt.Printf("\n  %d. %s\n", i+1, clusterArn)
		listClustersOutput = append(listClustersOutput, fmt.Sprintf("Cluster %d: %s", i+1, clusterArn))

		// Describe each clusterDescription
		fmt.Printf("     🔍 Describing clusterDescription details...\n")

		clusterDescription, err := DescribeCluster(client, clusterArn)
		if err != nil {
			errorMsg := fmt.Sprintf("     ❌ Failed to describe clusterDescription %s: %v", clusterArn, err)
			fmt.Println(errorMsg)
			logToFile("Describe ECS Cluster", "ecs.Client.DescribeClusters()", "ERROR", errorMsg)
			listClustersOutput = append(listClustersOutput, fmt.Sprintf("  Description failed: %v", err))
			continue
		}

		if clusterDescription == nil {
			noDataMsg := "     ⚠️ No clusterDescription data returned"
			fmt.Println(noDataMsg)
			listClustersOutput = append(listClustersOutput, "  No clusterDescription data returned")
			continue
		}

		// Print clusterDescription details to terminal
		fmt.Printf("     ✅ Cluster Description:\n")
		fmt.Printf("        Name: %s\n", aws.ToString(clusterDescription.ClusterName))
		fmt.Printf("        ARN: %s\n", aws.ToString(clusterDescription.ClusterArn))
		fmt.Printf("        Status: %s\n", aws.ToString(clusterDescription.Status))
		fmt.Printf("        Running Tasks: %d\n", clusterDescription.RunningTasksCount)
		fmt.Printf("        Pending Tasks: %d\n", clusterDescription.PendingTasksCount)
		fmt.Printf("        Active Services: %d\n", clusterDescription.ActiveServicesCount)
		fmt.Printf("        Registered Container Instances: %d\n", clusterDescription.RegisteredContainerInstancesCount)

		if clusterDescription.CapacityProviders != nil && len(clusterDescription.CapacityProviders) > 0 {
			fmt.Printf("        Capacity Providers: %v\n", clusterDescription.CapacityProviders)
		}

		if clusterDescription.DefaultCapacityProviderStrategy != nil && len(clusterDescription.DefaultCapacityProviderStrategy) > 0 {
			fmt.Printf("        Default Capacity Provider Strategy:\n")
			for _, strategy := range clusterDescription.DefaultCapacityProviderStrategy {
				fmt.Printf("          - Provider: %s, Weight: %d, Base: %d\n",
					aws.ToString(strategy.CapacityProvider),
					strategy.Weight,
					strategy.Base)
			}
		}

		if clusterDescription.Tags != nil && len(clusterDescription.Tags) > 0 {
			fmt.Printf("        Tags:\n")
			for _, tag := range clusterDescription.Tags {
				fmt.Printf("          - %s: %s\n", aws.ToString(tag.Key), aws.ToString(tag.Value))
			}
		}

		// Add detailed clusterDescription info to output log
		clusterDetailStr := fmt.Sprintf("Cluster: %s | Status: %s | Running: %d | Pending: %d | Services: %d | Instances: %d",
			aws.ToString(clusterDescription.ClusterName),
			aws.ToString(clusterDescription.Status),
			clusterDescription.RunningTasksCount,
			clusterDescription.PendingTasksCount,
			clusterDescription.ActiveServicesCount,
			clusterDescription.RegisteredContainerInstancesCount)

		listClustersOutput = append(listClustersOutput, fmt.Sprintf("  %s", clusterDetailStr))

		// Log successful clusterDescription description
		logToFile("Describe ECS Cluster", "ecs.Client.DescribeClusters()", "SUCCESS", clusterDetailStr)

		// List containers in this clusterDescription
		fmt.Printf("\n")
		clusterContainers, err := listContainersInCluster(client, clusterDescription, region)
		if err != nil {
			fmt.Printf("     ⚠️ Failed to list containers in clusterDescription %s: %v\n", aws.ToString(clusterDescription.ClusterName), err)
		} else {
			fmt.Printf("     📋 Returned %d container objects from cluster\n", len(clusterContainers))
			// Add containers from this cluster to the total collection
			allContainers = append(allContainers, clusterContainers...)
		}
	}

	// Log to output file
	resultData := fmt.Sprintf("Found %d containers across %d clusters", len(allContainers), len(clustersList.ClusterArns))
	logToFile(requestName, sdkFunction, "SUCCESS", resultData)

	fmt.Printf("\n✅ Total containers collected: %d across %d clusters\n\n", len(allContainers), len(clustersList.ClusterArns))
	return allContainers, nil
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
	var results []FlatResourceResult

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

		// Print network analysis results
		fmt.Printf("   📊 Network Analysis Results:\n")
		fmt.Printf("      🔐 Publicly Exposed: %v\n", networkAnalysis.IsPubliclyExposed)
		fmt.Printf("      🌐 Network Mode: %s\n", networkAnalysis.NetworkMode)
		fmt.Printf("      🏠 Private IPs: %v\n", networkAnalysis.PrivateIPs)
		if len(networkAnalysis.PublicIPs) > 0 {
			fmt.Printf("      🌍 Public IPs: %v\n", networkAnalysis.PublicIPs)
		}
		if len(networkAnalysis.SecurityGroups) > 0 {
			fmt.Printf("      🛡️ Security Groups: %v\n", networkAnalysis.SecurityGroups)
		}
		if len(networkAnalysis.OpenPorts) > 0 {
			fmt.Printf("      🚪 Open Ports: %v\n", networkAnalysis.OpenPorts)
		}
		if len(networkAnalysis.ExposureReasons) > 0 {
			fmt.Printf("      📋 Exposure Reasons: %v\n", networkAnalysis.ExposureReasons)
		}
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

		results = append(results, result)
	}

	// Log the results as JSON string
	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to marshal results to JSON: %v\n", err)
		logToFile("MapAWSToFlatResource", "json.MarshalIndent()", "ERROR", fmt.Sprintf("Failed to marshal results: %v", err))
	} else {
		fmt.Printf("📄 MapAWSToFlatResource Results (JSON):\n%s\n", string(resultsJSON))
		logToFile("MapAWSToFlatResource", "json.MarshalIndent()", "SUCCESS", fmt.Sprintf("Mapped %d containers to FlatResourceResult", len(results)))
	}

	return results, nil
}

// These functions have been removed to prevent duplication.
// Network analysis is now handled directly in MapAWSToFlatResource.

func writeConfigToFile(region string) {
	// Log the file writing operation
	fmt.Println("🔍 Request: Write Configuration to File")
	fmt.Println("📞 SDK Function: os.Create() + file.WriteString()")
	fmt.Println("⏳ Writing configuration and logs to out.txt...")

	file, err := os.Create("out.txt")
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to create output file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "os.Create()", "ERROR", errorMsg)
		return
	}

	// Properly handle file closing with error checking
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			errorMsg := fmt.Sprintf("❌ Error closing file: %v", closeErr)
			fmt.Println(errorMsg)
			logToFile("Write Configuration File", "file.Close()", "ERROR", errorMsg)
		}
	}()

	// Configuration section
	content := fmt.Sprintf("AWS SDK v2 Configuration & Operation Log\n")
	content += fmt.Sprintf("=========================================\n")
	content += fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	content += fmt.Sprintf("CONFIGURATION:\n")
	content += fmt.Sprintf("--------------\n")
	content += fmt.Sprintf("Region: %s\n", region)
	content += fmt.Sprintf("ECS Package: github.com/aws/aws-sdk-go-v2/service/ecs\n")
	content += fmt.Sprintf("Config Package: github.com/aws/aws-sdk-go-v2/config\n")
	content += fmt.Sprintf("Profile: ASTProd-Developers-602005780816\n")
	content += fmt.Sprintf("AssumeRole ARN: %s\n", TargetRoleArn)

	content += fmt.Sprintf("\nCREDENTIAL OPTIONS:\n")
	content += fmt.Sprintf("-------------------\n")
	content += fmt.Sprintf("- Environment Variables\n")
	content += fmt.Sprintf("- AWS Credentials File\n")
	content += fmt.Sprintf("- IAM Roles\n")
	content += fmt.Sprintf("- AssumeRole with ARN\n")
	content += fmt.Sprintf("- Profile-based Configuration\n")

	// Operation logs section
	content += fmt.Sprintf("\nOPERATION LOGS:\n")
	content += fmt.Sprintf("---------------\n")
	if len(operationLogs) > 0 {
		for _, logEntry := range operationLogs {
			content += fmt.Sprintf("%s\n", logEntry)
		}
	} else {
		content += fmt.Sprintf("No operations logged yet.\n")
	}

	content += fmt.Sprintf("\nSetup completed successfully! ✅\n")

	// Write content with error handling
	bytesWritten, err := file.WriteString(content)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to write content to file: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "file.WriteString()", "ERROR", errorMsg)
		return
	}

	// Force write to disk
	if err := file.Sync(); err != nil {
		errorMsg := fmt.Sprintf("⚠️ Warning: Failed to sync file to disk: %v", err)
		fmt.Println(errorMsg)
		logToFile("Write Configuration File", "file.Sync()", "WARNING", errorMsg)
		// Don't return here as the write was successful, just sync failed
	}

	// Success message with detailed info
	successMsg := fmt.Sprintf("✅ Configuration and %d operation logs written to out.txt (%d bytes)",
		len(operationLogs), bytesWritten)
	fmt.Println(successMsg)
	logToFile("Write Configuration File", "writeConfigToFile()", "SUCCESS",
		fmt.Sprintf("Written %d operation logs, %d bytes", len(operationLogs), bytesWritten))
}
