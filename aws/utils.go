package aws

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
)

func ExportCSV(containers []ContainerData) bool {
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

func ExportJSON(containers []ContainerData) bool {
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
	if err := encoder.Encode(containers); err != nil {
		fmt.Printf("❌ Failed to write JSON data: %v\n", err)
		return false
	}

	fmt.Printf("✅ Successfully saved %d container records to containers.json\n", len(containers))
	return true
}
