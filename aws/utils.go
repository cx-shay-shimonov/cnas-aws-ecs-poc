package aws

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func ExportCSV(resources []FlatResourceResult) bool {
	fmt.Printf("💾 Saving %d results to containers.csv...\n", len(resources))

	// Create CSV file
	file, err := os.Create("containers.csv")
	if err != nil {
		log.Printf("❌ Failed to create CSV file: %v", err)
		return false
	}
	defer func( /*file *os.File*/ ) {
		err := file.Close()
		if err != nil {
			log.Printf("❌ Failed to close CSV file: %v", err)
		} else {
			fmt.Println("✅ CSV file closed successfully")
		}
	}( /*file*/ )

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV headers
	headers := []string{"ID", "Name", "Type", "Image", "ImageSha", "PublicExposed", "Correlation", "ClusterName", "ClusterType", "ProviderID", "Region", "Metadata"}
	if err := writer.Write(headers); err != nil {
		log.Printf("❌ Failed to write CSV headers: %v", err)
		return false
	}

	// Write each result as CSV row
	for _, result := range resources {
		// Handle metadata - convert map to key=value pairs
		metadataStr := ""
		if len(result.StoreResourceFlat.Metadata) > 0 {
			var metadataPairs []string
			for key, value := range result.StoreResourceFlat.Metadata {
				metadataPairs = append(metadataPairs, fmt.Sprintf("%s=%s", key, value))
			}
			metadataStr = strings.Join(metadataPairs, ";")
		}

		// Create CSV row
		row := []string{
			result.ID,
			result.StoreResourceFlat.Name,
			string(result.StoreResourceFlat.Type),
			result.StoreResourceFlat.Image,
			result.StoreResourceFlat.ImageSha,
			strconv.FormatBool(result.StoreResourceFlat.PublicExposed),
			result.StoreResourceFlat.Correlation,
			result.StoreResourceFlat.ClusterName,
			string(result.StoreResourceFlat.ClusterType),
			result.StoreResourceFlat.ProviderID,
			result.StoreResourceFlat.Region,
			metadataStr,
		}

		// Write row to CSV
		if err := writer.Write(row); err != nil {
			log.Printf("❌ Failed to write CSV row: %v", err)
			continue
		}
	}

	fmt.Printf("✅ Successfully saved %d container records to containers.csv\n", len(resources))
	return true
}
