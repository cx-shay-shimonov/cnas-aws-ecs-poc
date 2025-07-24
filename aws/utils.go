package aws

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"aws-ecs-project/model"
)

func ExportCSV(resources []model.FlatResource) bool {
	// Create CSV file
	csvFile, err := os.Create("containers.csv")
	if err != nil {
		fmt.Printf("❌ Failed to create CSV file: %v\n", err)
		return false
	}
	defer func() {
		err := csvFile.Close()
		if err != nil {
			fmt.Println("✅ CSV file closed successfully")
			return
		}
	}()

	// Create CSV writer
	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "Name", "Type", "Image", "ImageSha", "PublicExposed",
		"Correlation", "ClusterName", "ClusterType", "ProviderID", "Region",
	}
	if err := writer.Write(header); err != nil {
		fmt.Printf("❌ Failed to write CSV header: %v\n", err)
		return false
	}

	// Write data rows
	for _, resource := range resources {
		if resource.StoreResourceFlat == nil {
			continue
		}
		record := []string{
			resource.ID,
			resource.StoreResourceFlat.Name,
			string(resource.StoreResourceFlat.Type),
			resource.StoreResourceFlat.Image,
			resource.StoreResourceFlat.ImageSha,
			fmt.Sprintf("%t", resource.StoreResourceFlat.PublicExposed),
			resource.StoreResourceFlat.ClusterName,
			string(resource.StoreResourceFlat.ClusterType),
			resource.StoreResourceFlat.ProviderID,
			resource.StoreResourceFlat.Region,
		}
		if err := writer.Write(record); err != nil {
			fmt.Printf("❌ Failed to write CSV record: %v\n", err)
			return false
		}
	}

	fmt.Printf("✅ Successfully saved %d container records to containers.csv\n", len(resources))
	return true
}

func ExportJSON(resources []model.FlatResource) bool {
	// Create JSON file
	jsonFile, err := os.Create("containers.json")
	if err != nil {
		fmt.Printf("❌ Failed to create JSON file: %v\n", err)
		return false
	}
	defer func() {
		err := jsonFile.Close()
		if err != nil {
			fmt.Println("✅ JSON file closed successfully")
			return
		}
	}()

	// Create JSON encoder
	encoder := json.NewEncoder(jsonFile)
	encoder.SetIndent("", "  ") // Pretty print

	// Write JSON data
	if err := encoder.Encode(resources); err != nil {
		fmt.Printf("❌ Failed to write JSON data: %v\n", err)
		return false
	}

	fmt.Printf("✅ Successfully saved %d container records to containers.json\n", len(resources))
	return true
}
