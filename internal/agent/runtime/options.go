package runtime

import (
	"fmt"
	"strings"
)

type Mode string

const (
	ModeInMemory  Mode = "in_memory"
	ModeDataplane Mode = "dataplane"
)

type Options struct {
	Mode      Mode
	Dataplane DataplaneOptions
}

type DataplaneOptions struct {
	Interface string
}

func DefaultOptions() Options {
	return Options{Mode: ModeInMemory}
}

func (o Options) normalize() (Options, error) {
	mode, err := normalizeMode(o.Mode)
	if err != nil {
		return Options{}, err
	}
	o.Mode = mode
	o.Dataplane.Interface = strings.TrimSpace(o.Dataplane.Interface)
	return o, nil
}

func normalizeMode(mode Mode) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(string(mode))) {
	case "", "in_memory", "in-memory", "memory", "noop", "no-op":
		return ModeInMemory, nil
	case "dataplane":
		return ModeDataplane, nil
	default:
		return "", fmt.Errorf("agent runtime mode %q is not valid", mode)
	}
}
