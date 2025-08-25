package main

import (
	"github.com/aws/aws-sdk-go-v2/aws"

	cnasAws "aws-ecs-project/aws"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Global constant for the target role ARN
const DefaultRegion = "us-east-1" // Default region for getting all regions
const TargetRoleArn = "arn:aws:iam::822112283600:role/CnasTargetRole"
const DebugFastMode = false // Set to true for faster testing, skips region discovery

func main() {

	cnasLogger := initLogger()

	ctx := context.TODO()

	defaultCfg, err := cnasAws.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
	if err != nil {
		cnasLogger.Fatal().
			Str("region", DefaultRegion).
			Err(err).
			Msg("AWS Configuration failed for default region")
	}

	defaultEC2Client := ec2.NewFromConfig(defaultCfg)
	cnasLogger.Info().Msg("EC2 Client created successfully for region discovery")

	var regionsNames []string
	if DebugFastMode {
		regionsNames = []string{"eu-west-2", "us-east-1", "us-east-2"}
	} else {
		// Get all AWS regions
		regions, err := listRegions(ctx, defaultEC2Client, cnasLogger)
		if err != nil {
			cnasLogger.Fatal().
				Err(err).
				Msg("Failed to get AWS regions")
		}
		regionsNames = make([]string, 0)
		for _, region := range regions {
			regionsNames = append(regionsNames, aws.ToString(region.RegionName))
		}
		cnasLogger.Info().
			Int("count", len(regionsNames)).
			Strs("regions", regionsNames).
			Msg("Found AWS regions")
	}

	cnasLogger.Info().
		Int("count", len(regionsNames)).
		Strs("regions", regionsNames).
		Msg("Found regions to explore")

	if len(regionsNames) == 0 {
		cnasLogger.Warn().Msg("No regions found, skipping ECS discovery")
	}

	cfg, err := cnasAws.LoadAWSConfig(ctx, DefaultRegion, TargetRoleArn)
	if err != nil {
		cnasLogger.Fatal().
			Str("role", TargetRoleArn).
			Err(err).
			Msg("Failed to load AWS configuration for role")
	}

	startTime := time.Now()
	containersData := cnasAws.EcsCrawl(regionsNames, ctx, &cfg, cnasLogger)
	endTime := time.Now()
	scanDuration := endTime.Sub(startTime)

	// Count exposed containersData
	exposedCount := 0
	for _, container := range containersData {
		if container.PublicExposed {
			exposedCount++
		}
	}

	// Calculate exposure rate
	exposureRate := 0.0
	if len(containersData) > 0 {
		exposureRate = float64(exposedCount) / float64(len(containersData)) * 100.0
	}

	// Create metadata
	metadata := cnasAws.ScanMetadata{
		TotalScanTime:       scanDuration.String(),
		TotalScanTimeMs:     scanDuration.Milliseconds(),
		ScanStartTime:       startTime,
		ScanEndTime:         endTime,
		TotalContainers:     len(containersData),
		TotalPublicExposed:  exposedCount,
		TotalRegionsScanned: len(regionsNames),
		ExposureRate:        exposureRate,
	}

	// Save detailed results to CSV and JSON files after all regions are processed
	if len(containersData) > 0 {
		// Create channels to receive results from concurrent operations
		csvChan := make(chan bool, 1)
		jsonChan := make(chan bool, 1)

		// Run ExportCSV concurrently
		go func() {
			csvChan <- cnasAws.ExportCSV(containersData)
		}()

		// Run ExportJSON concurrently (with timing metadata)
		go func() {
			jsonChan <- cnasAws.ExportJSON(containersData, metadata)
		}()

		// Wait for both operations to complete and collect results
		csvSuccess := <-csvChan
		jsonSuccess := <-jsonChan

		// Report results
		if !csvSuccess {
			cnasLogger.Error().Msg("Failed to save results to CSV file")
		} else {
			cnasLogger.Info().Msg("Results saved to containers.csv successfully")
		}

		if !jsonSuccess {
			cnasLogger.Error().Msg("Failed to save results to JSON file")
		} else {
			cnasLogger.Info().Msg("Results saved to containers.json successfully")
		}
	} else {
		cnasLogger.Info().Msg("No containersData found to save to CSV or JSON")
	}
}

// initLogger initializes the zerolog cnasLogger with pretty console output
func initLogger() zerolog.Logger {
	// Configure zerolog for pretty console output
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	cnasLogger := zerolog.New(output).With().Timestamp().Logger()

	// Set global log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Also update the global zerolog cnasLogger
	log.Logger = cnasLogger

	cnasLogger.Info().Msg("Logger initialized")
	return cnasLogger
}

// listRegions gets all AWS regions using EC2 client
func listRegions(ctx context.Context, ec2Client *ec2.Client, cnasLogger zerolog.Logger) ([]types.Region, error) {
	cnasLogger.Info().Msg("Getting all AWS regions...")

	resp, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	return resp.Regions, nil
}
