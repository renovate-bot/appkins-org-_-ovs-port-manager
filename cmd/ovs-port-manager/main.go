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

	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(logrus.InfoLevel)
	log.SetOutput(os.Stdout)

	// Create and start the OVS port manager
	manager, err := manager.New(log)
	if err != nil {
		log.WithError(err).Fatal("Failed to create OVS port manager")
	}

	if err := manager.Start(ctx); err != nil {
		log.WithError(err).Fatal("OVS port manager failed")
	}
}
