package aws

import (
	ecsTypes "aws-ecs-project/aws/ecs_types"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ScanResults represents the complete scan output with results and metadata
type ScanResults struct {
	Results  []ecsTypes.ContainerData `json:"results"`
	Metadata ScanMetadata             `json:"metadata"`
}

// ScanMetadata contains timing and summary information about the scan
type ScanMetadata struct {
	TotalScanTime       string    `json:"total_scan_time"`       // e.g., "3.2s"
	TotalScanTimeMs     int64     `json:"total_scan_time_ms"`    // milliseconds
	ScanStartTime       time.Time `json:"scan_start_time"`       // ISO timestamp
	ScanEndTime         time.Time `json:"scan_end_time"`         // ISO timestamp
	TotalContainers     int       `json:"total_containers"`      // count
	TotalPublicExposed  int       `json:"total_public_exposed"`  // count
	TotalRegionsScanned int       `json:"total_regions_scanned"` // count
	ExposureRate        float64   `json:"exposure_rate"`         // percentage (0.0-100.0)
}

// ExportCSV exports container data to a CSV file named "containers.csv"
func ExportCSV(containers []ecsTypes.ContainerData) bool {
	// Create CSV file
	csvFile, err := os.Create("containers.csv")
	if err != nil {
		fmt.Printf("❌ Failed to create CSV file: %v\n", err)
		return false
	}
	defer func() {
		if err := csvFile.Close(); err != nil {
			fmt.Printf("⚠️ Failed to close CSV file: %v\n", err)
		}
	}()

	// Create CSV writer
	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write header
	header := []string{
		"Container", "Image", "image Sha", "PublicExposed",
		"ClusterName", "ProviderID", "Region",
	}
	if err := writer.Write(header); err != nil {
		fmt.Printf("❌ Failed to write CSV header: %v\n", err)
		return false
	}

	// Write data rows
	for _, container := range containers {

		record := []string{
			container.Name,
			container.Image,
			container.ImageSHA,
			fmt.Sprintf("%t", container.PublicExposed),
			container.ClusterName,
			container.TaskARN,
			container.Region,
		}
		if err := writer.Write(record); err != nil {
			fmt.Printf("❌ Failed to write CSV record: %v\n", err)
			return false
		}
	}

	fmt.Printf("✅ Successfully saved %d container records to containers.csv\n", len(containers))
	return true
}

// ExportJSON exports containers with comprehensive metadata including timing
func ExportJSON(containers []ecsTypes.ContainerData, metadata ScanMetadata) bool {
	// Create JSON file
	jsonFile, err := os.Create("containers.json")
	if err != nil {
		fmt.Printf("❌ Failed to create JSON file: %v\n", err)
		return false
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Printf("⚠️ Failed to close JSON file: %v\n", err)
		}
	}()

	// Create complete scan results structure
	scanResults := ScanResults{
		Results:  containers,
		Metadata: metadata,
	}

	// Create JSON encoder
	encoder := json.NewEncoder(jsonFile)
	encoder.SetIndent("", "  ") // Pretty print

	// Write JSON data
	if err := encoder.Encode(scanResults); err != nil {
		fmt.Printf("❌ Failed to write JSON data: %v\n", err)
		return false
	}

	fmt.Printf("✅ Successfully saved %d container records with metadata to containers.json\n", len(containers))
	fmt.Printf("📊 Scan completed in %s - %d/%d containers publicly exposed (%.1f%%)\n",
		metadata.TotalScanTime, metadata.TotalPublicExposed, metadata.TotalContainers, metadata.ExposureRate)
	return true
}
