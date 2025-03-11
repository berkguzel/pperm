package options

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

type Options struct {
	PodName       string
	Namespace     string
	ShowRole      bool
	ShowPolicies  bool
	ShowPerms     bool
	InspectPolicy bool
	KubeConfig    string
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

	// Process all arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--inspect-policy", "-i":
			o.InspectPolicy = true
		case "--role":
			o.ShowRole = true
		case "--policies":
			o.ShowPolicies = true
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
