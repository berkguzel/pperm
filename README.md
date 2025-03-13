# `pperm`: Kubernetes Pod Permission Analyzer for AWS IAM

`pperm` is a kubectl plugin that helps you analyze and audit AWS IAM permissions associated with your Kubernetes pods. It provides a quick and efficient way to understand what permissions your pods have through their service accounts and IAM roles, helping you identify security risks and ensure proper access controls.


## ✨ Features

- 🔍 **Policy Discovery**: Automatically detects all IAM policies attached to pod service accounts
- ⚠️ **Risk Assessment**: Identifies overly permissive policies and highlights high-risk permissions
- 📊 **Structured Output**: Presents permissions in well-formatted tables for easy analysis
- 🔄 **Interactive Inspection**: Allows deep-diving into specific policies with an interactive CLI
- 🔒 **Security Insights**: Provides context about permission scope and potential security implications

## 🚀 Installation

### Prerequisites

- Kubernetes cluster with AWS IAM integration (e.g., EKS with IRSA, EKS Pod Identity)
- `kubectl` installed
- AWS credentials configured with permissions to read IAM policies
- Go 1.19 or later (for building from source)

### Installation Options

#### Building from Source (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/berkguzel/pperm.git
cd pperm
```

2. Build the binary:
```bash
go build -o pperm cmd/kubectl-pperm/main.go
```

3. Make it executable and move to your PATH to use as a kubectl plugin:
```bash
chmod +x pperm
sudo mv pperm /usr/local/bin/kubectl-pperm
```

4. Verify the installation:
```bash
kubectl pperm --help
```

## 📋 Usage

### Basic Commands

```bash
# Show policy overview (default behavior)
kubectl pperm <pod-name>

# Show detailed permissions list
kubectl pperm <pod-name> --permissions

# Show only high-risk permissions
kubectl pperm <pod-name> --risk-only

# Inspect specific policies interactively
kubectl pperm <pod-name> --inspect-policy

```

### Examples

#### Policy Overview

```bash
$ kubectl pperm nginx-pod
+--------------------------------+---------+----------------+------------+--------------+
| POLICY NAME                    | SERVICE | ACCESS LEVEL   | RESOURCE   | CONDITION    |
+--------------------------------+---------+----------------+------------+--------------+
| AmazonEC2ReadOnlyAccess        | EC2     | Read-Only      | *          | No           |
| AmazonS3FullAccess             | S3      | Full Access    | *          | No           |
+--------------------------------+---------+----------------+------------+--------------+
```

#### Detailed Permissions

```bash
$ kubectl pperm nginx-pod --permissions
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
| POLICY                         | ACTION                              | RESOURCE                                                      | SCOPE |
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
| AmazonS3FullAccess             | s3:*                                | *                                                             |  🚨   |
| AmazonS3FullAccess             | s3-object-lambda:*                  | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | ec2:Describe*                       | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | ec2:GetSecurityGroupsForVpc         | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | elasticloadbalancing:Describe*      | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:ListMetrics              | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:GetMetricStatistics      | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:Describe*                | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | autoscaling:Describe*               | *                                                             |  🚨   |
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
```

#### Risk-Only View

```bash
$ kubectl pperm nginx-pod --risk-only
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
| POLICY                         | ACTION                              | RESOURCE                                                      | SCOPE |
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
| AmazonS3FullAccess             | s3:*                                | *                                                             |  🚨   |
| AmazonS3FullAccess             | s3-object-lambda:*                  | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | ec2:Describe*                       | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | ec2:GetSecurityGroupsForVpc         | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | elasticloadbalancing:Describe*      | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:ListMetrics              | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:GetMetricStatistics      | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:Describe*                | *                                                             |  🚨   |
| AmazonEC2ReadOnlyAccess        | autoscaling:Describe*               | *                                                             |  🚨   |
+--------------------------------+-------------------------------------+---------------------------------------------------------------+-------+
```

#### Interactive Policy Inspection

```bash
$ kubectl pperm test-pod --inspect-policy

Pod: test-pod
Service Account: test-sa
IAM Role: arn:aws:iam::123456789012:role/test-role

Available Policies:
------------------
1. AmazonEC2ReadOnlyAccess
2. AmazonS3FullAccess

Enter policy number to inspect (or 0 to exit): 1

Policy: AmazonEC2ReadOnlyAccess
ARN: arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess

Permissions:
-----------
+--------------------------------+-------------------------------------+------------------------------------------------------+-------+
| POLICY                         | ACTION                              | RESOURCE                                             | SCOPE |
+--------------------------------+-------------------------------------+------------------------------------------------------+-------+
| AmazonEC2ReadOnlyAccess        | ec2:Describe*                       | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | ec2:GetSecurityGroupsForVpc         | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | elasticloadbalancing:Describe*      | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:ListMetrics              | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:GetMetricStatistics      | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | cloudwatch:Describe*                | *                                                    |  🚨   |
| AmazonEC2ReadOnlyAccess        | autoscaling:Describe*               | *                                                    |  🚨   |
+--------------------------------+-------------------------------------+------------------------------------------------------+-------+

Access Level: Read-Only
Service: EC2
Resource Scope: *
Has Conditions: No
```
## 🔧 Configuration

### Command Line Options

| Flag | Description |
|------|-------------|
| (no flags) | Show policy overview table (default behavior) |
| `--permissions` | Show detailed permissions instead of policy overview |
| `--risk-only`, `-r` | Show only high-risk permissions |
| `--inspect-policy`, `-i` | Enter interactive mode to inspect specific policies |
| `-h, --help` | Show help information |

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please make sure to update tests as appropriate.

## 🙏 Acknowledgments

This project was developed with the assistance of [Cursor AI](https://cursor.sh/).

## 📝 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
