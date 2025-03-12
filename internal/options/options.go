package options

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

type Options struct {
	PodName       string
	Namespace     string
	ShowPerms     bool
	InspectPolicy bool
	RiskOnly      bool
	KubeConfig    string
	Help          bool
}

func printUsage() {
	fmt.Printf(`Usage: kubectl pperm [flags] POD_NAME

Display AWS IAM permissions for pods in Kubernetes clusters.

Flags:
  -h, --help              Show help message
  -i, --inspect-policy    Inspect detailed policy information
  -r, --risk-only        Show only permissions with high risk or broad scope
  --permissions          Show detailed permissions list

Examples:
  # Show policy overview (default)
  kubectl pperm my-pod

  # Show only high-risk permissions
  kubectl pperm my-pod -r

  # Show detailed permissions list
  kubectl pperm my-pod --permissions

  # Inspect detailed policy information
  kubectl pperm my-pod -i

Kubernetes flags like -n/--namespace are also supported.
`)
}

func NewOptions() *Options {
	// Check KUBECONFIG env var first
	kubeconfig := ""
	if envPath := os.Getenv("KUBECONFIG"); envPath != "" {
		kubeconfig = envPath
	} else {
		// Fall back to default path
		home, _ := homedir.Dir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	return &Options{
		KubeConfig: kubeconfig,
		Namespace:  "default",
	}
}

func (o *Options) Parse() error {
	args := os.Args[1:] // Skip program name

	// Check for help flag first
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			o.Help = true
			printUsage()
			return nil
		}
	}

	// Process all arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--inspect-policy", "-i":
			o.InspectPolicy = true
		case "--risk-only", "-r":
			o.RiskOnly = true
		case "--permissions":
			o.ShowPerms = true
		case "-n", "--namespace":
			if i+1 < len(args) {
				i++
				o.Namespace = args[i]
			}
		case "--kubeconfig":
			if i+1 < len(args) {
				i++
				o.KubeConfig = args[i]
			}
		default:
			// If it doesn't start with '-', treat it as pod name
			if !strings.HasPrefix(arg, "-") {
				o.PodName = arg
			}
		}
	}

	return nil
}
