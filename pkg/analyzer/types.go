package analyzer

type StatementInfo struct {
	Effect    string
	Actions   []string
	Resources []string
}

type Warning struct {
	Level       string // High, Medium, Low
	Description string
	Action      string
}

// High-risk permissions that should trigger warnings
var HighRiskPermissions = map[string]string{
	"iam:*":                "Full IAM access",
	"s3:*":                "Full S3 access",
	"dynamodb:*":          "Full DynamoDB access",
	"secretsmanager:*":    "Full Secrets Manager access",
	"kms:*":              "Full KMS access",
	"ec2:*":              "Full EC2 access",
}