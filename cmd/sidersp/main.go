package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sidersp/internal/config"
	"sidersp/internal/controlplane"
	"sidersp/internal/dataplane"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config file")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig := <-sigCh
		log.Printf("sidersp stopping signal=%s", sig)
		cancel()
	}()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config %s: %v", *configPath, err)
	}

	dp, err := dataplane.Open(dataplane.Options{
		Interface:  cfg.Dataplane.Interface,
		AttachMode: cfg.Dataplane.AttachMode,
	})
	if err != nil {
		log.Fatalf("open dataplane: %v", err)
	}
	defer func() {
		if err := dp.Close(); err != nil {
			log.Printf("close dataplane: %v", err)
		}
	}()

	cp := controlplane.NewRuntime(cfg, dp, log.Default())
	log.Printf("sidersp starting config=%s iface=%s", *configPath, cfg.Dataplane.Interface)
	if err := cp.Run(ctx); err != nil {
		log.Fatalf("run controlplane: %v", err)
	}
}
