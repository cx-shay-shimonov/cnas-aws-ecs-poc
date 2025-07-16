# 🔐 AWS Credentials Configuration Guide

## 🎯 **WHERE TO PUT ARN CREDENTIALS**

### Current Code Location
The credential configuration is in the `loadAWSConfig()` function in `main.go` (lines 56-126).

### **OPTION 1: AssumeRole with ARN (Most Common)**

**📍 Location:** Replace the commented code in `loadAWSConfig()` function

```go
// ADD THESE IMPORTS AT THE TOP OF main.go:
import (
    // ... existing imports ...
    "github.com/aws/aws-sdk-go-v2/credentials/stscreds"
    "github.com/aws/aws-sdk-go-v2/service/sts"
)

// REPLACE the loadAWSConfig function with this:
func loadAWSConfig(ctx context.Context) (config.Config, error) {
    // Load default config first
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion("eu-west-1"),
    )
    if err != nil {
        return cfg, err
    }
    
    // Create STS client for assuming role
    stsClient := sts.NewFromConfig(cfg)
    
    // 🎯 PUT YOUR ROLE ARN HERE:
    roleArn := "arn:aws:iam::123456789012:role/YourRoleName"
    
    // AssumeRole credentials provider
    cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(o *stscreds.AssumeRoleOptions) {
        o.RoleSessionName = "aws-ecs-session"
        o.ExternalID = "your-external-id"  // If required
        // o.Duration = time.Hour           // Optional: session duration
    })
    
    return cfg, nil
}
```

### **OPTION 2: Environment Variable for Role ARN**

**📍 Location:** Set environment variable, then use this code:

```bash
# Set your role ARN as environment variable:
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/YourRoleName"
```

```go
// ADD TO loadAWSConfig function:
roleArn := os.Getenv("AWS_ROLE_ARN")
if roleArn != "" {
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion("eu-west-1"),
    )
    if err != nil {
        return cfg, err
    }
    
    stsClient := sts.NewFromConfig(cfg)
    cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, roleArn)
    return cfg, nil
}
```

### **OPTION 3: Direct Credentials (NOT RECOMMENDED for production)**

**📍 Location:** Replace in `loadAWSConfig()` function

```go
// ADD THIS IMPORT:
import "github.com/aws/aws-sdk-go-v2/credentials"

// 🔴 NEVER do this in production!
cfg, err := config.LoadDefaultConfig(ctx,
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        "AKIAIOSFODNN7EXAMPLE",    // 🔴 Your access key
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // 🔴 Your secret key
        "",                        // Session token (leave empty)
    )),
    config.WithRegion("eu-west-1"),
)
```

## 🔧 **How to Modify the Current Code**

### Step 1: Choose Your Method
Pick one of the options above based on your use case:
- **AssumeRole** → Cross-account access or temporary credentials
- **Environment Variable** → Flexibility without code changes
- **Direct Credentials** → Only for testing (never production)

### Step 2: Update main.go
Replace the current simple configuration in `main()` function:

```go
// CURRENT CODE (line ~16 in main.go):
cfg, err := config.LoadDefaultConfig(ctx,
    config.WithRegion("eu-west-1"),
)

// REPLACE WITH:
cfg, err := loadAWSConfig(ctx)
```

### Step 3: Implement Your Chosen Method
Uncomment and modify the relevant section in the `loadAWSConfig()` function.

## 📋 **Quick Setup Checklist**

- [ ] Choose credential method (AssumeRole recommended)
- [ ] Add required imports if using AssumeRole/direct credentials
- [ ] Update `loadAWSConfig()` function with your method
- [ ] Replace your ARN/credentials in the code
- [ ] Update main() to call `loadAWSConfig(ctx)` instead of `config.LoadDefaultConfig()`
- [ ] Test with: `go run main.go`

## 🚨 **Security Best Practices**

1. **✅ DO:** Use AssumeRole with ARN for production
2. **✅ DO:** Use environment variables for configuration
3. **✅ DO:** Use IAM roles when running on AWS infrastructure
4. **❌ DON'T:** Hardcode credentials in source code
5. **❌ DON'T:** Commit credentials to version control
6. **❌ DON'T:** Use direct credentials in production

## 🔍 **Example ARN Formats**

```bash
# IAM Role ARN:
arn:aws:iam::123456789012:role/MyRole

# Cross-account role ARN:
arn:aws:iam::987654321098:role/CrossAccountRole

# Role with path:
arn:aws:iam::123456789012:role/MyPath/MyRole
```

## ✅ **Testing Your Configuration**

After implementing your chosen method:

```bash
go run main.go
```

**Success indicators:**
- ✅ "ECS Client created successfully"
- ✅ "ECS Client created successfully"
- ✅ No credential errors (if properly configured)

**If you see credential errors:**
- Check your ARN is correct
- Verify the role exists and you have permission to assume it
- Ensure your base AWS credentials are configured 