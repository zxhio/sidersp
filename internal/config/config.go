package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Dataplane    DataplaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
	Console      ConsoleConfig      `yaml:"console"`
}

type ControlPlaneConfig struct {
	RulesPath string `yaml:"rules_path"`
}

type DataplaneConfig struct {
	Interface  string `yaml:"interface"`
	AttachMode string `yaml:"attach_mode"`
}

type ConsoleConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
func (c Config) validate() error {
	if strings.TrimSpace(c.Dataplane.Interface) == "" {
		return fmt.Errorf("dataplane.interface is required")
	}
	if strings.TrimSpace(c.ControlPlane.RulesPath) == "" {
		return fmt.Errorf("controlplane.rules_path is required")
	}
	if strings.TrimSpace(c.Console.ListenAddr) == "" {
		return fmt.Errorf("console.listen_addr is required")
	}

	return nil
}
