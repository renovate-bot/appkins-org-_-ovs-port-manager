package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/appkins-org/ovs-port-manager/internal/manager"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

func main() {
	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Create a logr logger using zap
	zapLogger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()

	logger := zapr.NewLogger(zapLogger)

	// Create and start the OVS port manager
	manager, err := manager.New(logger)
	if err != nil {
		logger.Error(err, "Failed to create OVS port manager")
		os.Exit(1)
	}

	if err := manager.Start(ctx); err != nil {
		logger.Error(err, "OVS port manager failed")
		os.Exit(1)
	}
}
