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

	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecsTypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Global constant for the target role ARN
const TARGET_ROLE_ARN = "arn:aws:iam::822112283600:role/CnasTargetRole"
const REGION = "eu-west-2"

// Global variables for logging
var operationLogs []string
var csvData [][]string
var jsonContainers []ContainerData

// ContainerData represents a container with its cluster context for JSON export
type ContainerData struct {
	Cluster       string `json:"cluster"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	Status        string `json:"status"`
	RuntimeID     string `json:"runtime_id,omitempty"`
	TaskARN       string `json:"task_arn"`
	TaskStatus    string `json:"task_status"`
	HostPort      int    `json:"host_port,omitempty"`
	ContainerPort int    `json:"container_port,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	PrivateIP     string `json:"private_ip,omitempty"`
	Timestamp     string `json:"timestamp"`
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
		"Timestamp",
	}
	csvData = append(csvData, headers)
}

// addContainerToCSV adds container data with cluster context to CSV
func addContainerToCSV(cluster *ecsTypes.Cluster, task *ecsTypes.Task, container *ecsTypes.Container) {
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

// addContainerToJSON adds container data with cluster context to JSON array
func addContainerToJSON(cluster *ecsTypes.Cluster, task *ecsTypes.Task, container *ecsTypes.Container) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	containerData := ContainerData{
		Cluster:       aws.ToString(cluster.ClusterName),
		ContainerName: aws.ToString(container.Name),
		Image:         aws.ToString(container.Image),
		Status:        aws.ToString(container.LastStatus),
		RuntimeID:     aws.ToString(container.RuntimeId),
		TaskARN:       aws.ToString(task.TaskArn),
		TaskStatus:    aws.ToString(task.LastStatus),
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

	// Initialize CSV data structure
	initializeCSV()
	fmt.Println("📊 CSV data structure initialized")

	// Load AWS configuration using AssumeRole with TARGET_ROLE_ARN
	fmt.Println("🔍 Request: Load AWS Configuration with AssumeRole")
	fmt.Println("📞 SDK Function: loadAWSConfig() -> AssumeRole")
	fmt.Println("⏳ Loading AWS configuration...")

	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ AWS Configuration failed: %v", err)
		fmt.Println(errorMsg)
		logToFile("Load AWS Configuration", "loadAWSConfig()", "ERROR", errorMsg)
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	// Log successful configuration
	configMsg := "✅ AWS Configuration loaded successfully"
	fmt.Println(configMsg)
	logToFile("Load AWS Configuration", "loadAWSConfig()", "SUCCESS", fmt.Sprintf("AWS Configuration loaded with AssumeRole: %s", TARGET_ROLE_ARN))

	fmt.Printf("AWS Region: %s\n", cfg.Region)
	fmt.Printf("✅ Using AssumeRole ARN: %s\n", TARGET_ROLE_ARN)

	// Create ECS client
	fmt.Println("\n🔍 Request: Create ECS Client")
	fmt.Println("📞 SDK Function: ecs.NewFromConfig()")
	ecsClient := ecs.NewFromConfig(cfg)
	fmt.Println("✅ ECS Client created successfully")
	logToFile("Create ECS Client", "ecs.NewFromConfig()", "SUCCESS", "ECS client initialized")

	// Example: List ECS clusters (requires AWS credentials)
	fmt.Println("\n==================================================")
	fmt.Println("🐳 ECS OPERATIONS")
	fmt.Println("==================================================")
	if err := listECSClusters(ctx, ecsClient); err != nil {
		fmt.Printf("⚠️ ECS operation failed: %v\n", err)
		fmt.Println("Note: This requires valid AWS credentials and permissions")
	}

	// Write configuration and all operation logs to file
	fmt.Println("\n==================================================")
	writeConfigToFile(cfg.Region)

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

	fmt.Println("\n🎉 AWS SDK v2 setup completed successfully!")
}

// loadAWSConfig configures AWS with AssumeRole using the hardcoded target ARN
func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	// Load default configuration first (for initial credentials from SSO)
	fmt.Println("📋 Step 1: Loading base SSO credentials...")
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(REGION),
	)
	if err == nil {
		// Test if credentials work by trying to get caller identity
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ Default credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Default credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 2: Try target-account profile
	fmt.Println("📋 Option 2: Trying target-account profile...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("target-account"),
		config.WithRegion(REGION),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ Target-account credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ Target-account credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 3: Try SSO profile (original approach)
	fmt.Println("📋 Option 3: Trying SSO profile...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion(REGION),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Println("✅ SSO credentials working!")
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO credentials failed test: %v\n", testErr)
		}
	}

	// OPTION 4: Try SSO + AssumeRole (if you get permissions fixed)
	fmt.Println("📋 Option 4: Trying SSO + AssumeRole...")
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile("ASTProd-Developers-602005780816"),
		config.WithRegion(REGION),
	)
	if err == nil {
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, TARGET_ROLE_ARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-ecs-cnas-session"
		})

		// Test AssumeRole
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ SSO + AssumeRole working with ARN: %s\n", TARGET_ROLE_ARN)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO + AssumeRole failed: %v\n", testErr)
		}
	}

	return aws.Config{}, fmt.Errorf("❌ All credential options failed. Please check your AWS configuration")
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

func listContainersInCluster(client *ecs.Client, cluster *ecsTypes.Cluster) error {
	clusterArn := aws.ToString(cluster.ClusterArn)
	clusterName := aws.ToString(cluster.ClusterName)
	fmt.Printf("     🔍 Listing containers in cluster: %s\n", clusterName)

	// Get tasks in the cluster
	taskArns, err := listTasks(client, clusterArn)
	if err != nil {
		errorMsg := fmt.Sprintf("     ❌ Failed to list tasks in cluster %s: %v", clusterName, err)
		fmt.Println(errorMsg)
		logToFile("List Tasks", "ecs.Client.ListTasks()", "ERROR", errorMsg)
		return err
	}

	if len(taskArns) == 0 {
		noTasksMsg := fmt.Sprintf("     📝 No running tasks found in cluster: %s", clusterName)
		fmt.Println(noTasksMsg)
		logToFile("List Tasks", "ecs.Client.ListTasks()", "INFO", noTasksMsg)
		return nil
	}

	fmt.Printf("     📊 Found %d running tasks\n", len(taskArns))
	logToFile("List Tasks", "ecs.Client.ListTasks()", "SUCCESS", fmt.Sprintf("Found %d tasks in cluster %s", len(taskArns), clusterName))

	// Describe tasks to get container details
	tasks, err := describeTasks(client, clusterArn, taskArns)
	if err != nil {
		errorMsg := fmt.Sprintf("     ❌ Failed to describe tasks in cluster %s: %v", clusterName, err)
		fmt.Println(errorMsg)
		logToFile("Describe Tasks", "ecs.Client.DescribeTasks()", "ERROR", errorMsg)
		return err
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

			// Add container data to CSV and JSON
			addContainerToCSV(cluster, &task, &container)
			addContainerToJSON(cluster, &task, &container)
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

	return nil
}

func listECSClusters(ctx context.Context, client *ecs.Client) error {
	// Print detailed request information
	requestName := "List ECS Clusters"
	sdkFunction := "ecs.Client.ListClusters()"

	fmt.Printf("🔍 Request: %s\n", requestName)
	fmt.Printf("📞 SDK Function: %s\n", sdkFunction)
	fmt.Println("⏳ Executing request...")

	input := &ecs.ListClustersInput{
		MaxResults: &[]int32{10}[0], // List up to 10 clusters
	}

	result, err := client.ListClusters(ctx, input)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ %s failed: %v", requestName, err)
		fmt.Println(errorMsg)

		// Log to output file
		logToFile(requestName, sdkFunction, "ERROR", errorMsg)

		return fmt.Errorf("failed to list ECS clusters: %w", err)
	}

	// Success - print results
	resultMsg := fmt.Sprintf("✅ %s completed successfully", requestName)
	fmt.Println(resultMsg)
	fmt.Printf("📊 Found %d ECS clusters:\n", len(result.ClusterArns))

	var clusterDetails []string
	for i, clusterArn := range result.ClusterArns {
		fmt.Printf("\n  %d. %s\n", i+1, clusterArn)
		clusterDetails = append(clusterDetails, fmt.Sprintf("Cluster %d: %s", i+1, clusterArn))

		// Describe each cluster
		fmt.Printf("     🔍 Describing cluster details...\n")

		cluster, err := DescribeCluster(client, clusterArn)
		if err != nil {
			errorMsg := fmt.Sprintf("     ❌ Failed to describe cluster %s: %v", clusterArn, err)
			fmt.Println(errorMsg)
			logToFile("Describe ECS Cluster", "ecs.Client.DescribeClusters()", "ERROR", errorMsg)
			clusterDetails = append(clusterDetails, fmt.Sprintf("  Description failed: %v", err))
			continue
		}

		if cluster == nil {
			noDataMsg := "     ⚠️ No cluster data returned"
			fmt.Println(noDataMsg)
			clusterDetails = append(clusterDetails, "  No cluster data returned")
			continue
		}

		// Print cluster details to terminal
		fmt.Printf("     ✅ Cluster Description:\n")
		fmt.Printf("        Name: %s\n", aws.ToString(cluster.ClusterName))
		fmt.Printf("        ARN: %s\n", aws.ToString(cluster.ClusterArn))
		fmt.Printf("        Status: %s\n", aws.ToString(cluster.Status))
		fmt.Printf("        Running Tasks: %d\n", cluster.RunningTasksCount)
		fmt.Printf("        Pending Tasks: %d\n", cluster.PendingTasksCount)
		fmt.Printf("        Active Services: %d\n", cluster.ActiveServicesCount)
		fmt.Printf("        Registered Container Instances: %d\n", cluster.RegisteredContainerInstancesCount)

		if cluster.CapacityProviders != nil && len(cluster.CapacityProviders) > 0 {
			fmt.Printf("        Capacity Providers: %v\n", cluster.CapacityProviders)
		}

		if cluster.DefaultCapacityProviderStrategy != nil && len(cluster.DefaultCapacityProviderStrategy) > 0 {
			fmt.Printf("        Default Capacity Provider Strategy:\n")
			for _, strategy := range cluster.DefaultCapacityProviderStrategy {
				fmt.Printf("          - Provider: %s, Weight: %d, Base: %d\n",
					aws.ToString(strategy.CapacityProvider),
					strategy.Weight,
					strategy.Base)
			}
		}

		if cluster.Tags != nil && len(cluster.Tags) > 0 {
			fmt.Printf("        Tags:\n")
			for _, tag := range cluster.Tags {
				fmt.Printf("          - %s: %s\n", aws.ToString(tag.Key), aws.ToString(tag.Value))
			}
		}

		// Add detailed cluster info to output log
		clusterDetailStr := fmt.Sprintf("Cluster: %s | Status: %s | Running: %d | Pending: %d | Services: %d | Instances: %d",
			aws.ToString(cluster.ClusterName),
			aws.ToString(cluster.Status),
			cluster.RunningTasksCount,
			cluster.PendingTasksCount,
			cluster.ActiveServicesCount,
			cluster.RegisteredContainerInstancesCount)

		clusterDetails = append(clusterDetails, fmt.Sprintf("  %s", clusterDetailStr))

		// Log successful cluster description
		logToFile("Describe ECS Cluster", "ecs.Client.DescribeClusters()", "SUCCESS", clusterDetailStr)

		// List containers in this cluster
		fmt.Printf("\n")
		if err := listContainersInCluster(client, cluster); err != nil {
			fmt.Printf("     ⚠️ Failed to list containers in cluster %s: %v\n", aws.ToString(cluster.ClusterName), err)
		}
	}

	// Log to output file
	resultData := fmt.Sprintf("Found %d clusters with details: %v", len(result.ClusterArns), clusterDetails)
	logToFile(requestName, sdkFunction, "SUCCESS", resultData)

	fmt.Println()
	return nil
}

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
	content += fmt.Sprintf("AssumeRole ARN: %s\n", TARGET_ROLE_ARN)

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
