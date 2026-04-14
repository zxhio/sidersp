package main

import (
	"flag"
	"log"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config file")
	flag.Parse()

	log.Printf("sidersp started config=%s", *configPath)
}
