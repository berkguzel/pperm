package options

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

type Options struct {
	PodName      string
	Namespace    string
	ShowRole     bool
	ShowPolicies bool
	ShowPerms    bool
	KubeConfig   string // Add this field
}

func NewOptions() *Options {
	home, _ := homedir.Dir()
	defaultKubeconfig := filepath.Join(home, ".kube", "config")
	return &Options{
		KubeConfig: defaultKubeconfig,
		Namespace:  "default",
	}
}

func (o *Options) Parse() error {
	flags := flag.NewFlagSet("kubectl-pperm", flag.ExitOnError)
	flags.StringVar(&o.Namespace, "n", o.Namespace, "Namespace")
	flags.BoolVar(&o.ShowRole, "role", false, "Show only IAM role")
	flags.BoolVar(&o.ShowPolicies, "policies", false, "Show attached policies")
	flags.BoolVar(&o.ShowPerms, "permissions", false, "Show detailed permissions")
	flags.StringVar(&o.KubeConfig, "kubeconfig", o.KubeConfig, "Path to kubeconfig file")

	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}

	// Get pod name from the first non-flag argument
	args := flags.Args()
	if len(args) > 0 {
		o.PodName = args[0]
	}

	return nil
}
