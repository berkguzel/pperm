package main

import (
	"os"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/analyzer"
	"github.com/berkguzel/pperm/pkg/aws"
	"github.com/berkguzel/pperm/pkg/kubernetes"
	"github.com/berkguzel/pperm/pkg/printer"
)

func main() {
	opts := options.NewOptions()
	if err := opts.Parse(); err != nil {
		os.Exit(1)
	}

	if err := run(opts); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(opts *options.Options) error {
	// Initialize kubernetes client
	k8sClient, err := kubernetes.NewClient(opts.KubeConfig)
	if err != nil {
		return err
	}

	// Initialize AWS client
    awsClient, err := aws.NewClient()
    if err != nil {
        return err
    }

	// Create analyzer
	analyzer := analyzer.New(k8sClient, awsClient)

	// Run analysis
	results, err := analyzer.Analyze(opts)
	if err != nil {
		return err
	}
	
	return printer.Print(results, opts)
}