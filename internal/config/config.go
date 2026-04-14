package config

import "errors"

type Config struct {
	Platform struct {
		Name string
		Mode string
	}
	ControlPlane struct {
		RulesPath string
	}
	Console struct {
		ListenAddr string
	}
}

func Load(path string) (Config, error) {
	_ = path
	return Config{}, errors.New("config loading is not implemented yet")
}
