package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/appkins-org/ovs-port-manager/internal/manager"
	"github.com/sirupsen/logrus"
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

	// Create and start the OVS port manager
	manager, err := manager.New()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create OVS port manager")
	}

	if err := manager.Start(ctx); err != nil {
		logrus.WithError(err).Fatal("OVS port manager failed")
	}
}
