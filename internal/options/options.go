package options

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"k8s.io/client-go/tools/clientcmd"
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

// getCurrentNamespace gets the current namespace from the kubeconfig
func getCurrentNamespace(kubeconfigPath string) string {
	// Load the kubeconfig file
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return "default" // Fall back to default namespace on error
	}

	// Get the current context
	currentContext := config.CurrentContext
	if currentContext == "" {
		return "default"
	}

	// Get the context details
	context, exists := config.Contexts[currentContext]
	if !exists || context == nil {
		return "default"
	}

	// Get the namespace from the context
	if context.Namespace != "" {
		return context.Namespace
	}

	return "default"
}

func printUsage() {
	fmt.Printf(`Usage: kubectl pperm [flags] POD_NAME

Display AWS IAM permissions for pods in Kubernetes clusters.

Flags:
  -h, --help              Show help message
  -i, --inspect-policy    Inspect detailed policy information
  -r, --risk-only         Show only permissions with high risk or broad scope
  --permissions           Show detailed permissions list
  -n, --namespace         Namespace of the pod (defaults to current namespace)

Examples:
  # Show policy overview (default behavior)
  kubectl pperm my-pod

  # Show only high-risk permissions
  kubectl pperm my-pod -r

  # Show detailed permissions list
  kubectl pperm my-pod --permissions

  # Inspect detailed policy information
  kubectl pperm my-pod -i

  # Specify a namespace
  kubectl pperm my-pod -n my-namespace

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

	// Get the current namespace from kubeconfig
	currentNamespace := getCurrentNamespace(kubeconfig)

	return &Options{
		KubeConfig: kubeconfig,
		Namespace:  currentNamespace,
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
