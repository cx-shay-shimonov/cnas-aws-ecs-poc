package aws

import (
	"context"
	"fmt"
	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// LoadAWSConfig configures AWS with AssumeRole for a specific region
func LoadAWSConfig(ctx context.Context, region string, roleArn string) (aws2.Config, error) {
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
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-ecs-cnas-session"
		})

		// Test AssumeRole
		if _, testErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); testErr == nil {
			fmt.Printf("✅ SSO + AssumeRole working with ARN: %s for region %s\n", roleArn, region)
			return cfg, nil
		} else {
			fmt.Printf("⚠️ SSO + AssumeRole failed for region %s: %v\n", region, testErr)
		}
	}

	return aws2.Config{}, fmt.Errorf("❌ All credential options failed for region %s. Please check your AWS configuration", region)
}
