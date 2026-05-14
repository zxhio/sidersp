package runtime

import (
	"net"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/service"
	"sidersp/internal/dataplane"
)

type Services struct {
	Status      *service.StatusService
	Ruleset     *service.RulesetService
	Attachments *service.AttachmentService
	Response    *service.ResponseService
	Dispatch    *service.DispatchService
	Stats       *service.StatsService
	Events      *service.EventService
}

type Composition struct {
	Services Services
	mode     Mode
	closer   interface {
		Close() error
	}
}

type DataplaneRuntime interface {
	service.DataplaneStatsReader
	service.DataplaneEventSource
	Attach() error
	ProgramID() (uint32, error)
	Close() error
}

type DataplaneOpener func(dataplane.Options) (DataplaneRuntime, error)

type interfaceLookup func(index int) (*net.Interface, error)

type buildOptions struct {
	dataplaneOpener  DataplaneOpener
	interfaceByIndex interfaceLookup
}

type BuildOption func(*buildOptions)

func WithDataplaneOpener(opener DataplaneOpener) BuildOption {
	return func(options *buildOptions) {
		options.dataplaneOpener = opener
	}
}

func WithInterfaceLookup(lookup interfaceLookup) BuildOption {
	return func(options *buildOptions) {
		options.interfaceByIndex = lookup
	}
}

func NewComposition(options Options, buildOpts ...BuildOption) (*Composition, error) {
	options, err := options.normalize()
	if err != nil {
		return nil, err
	}

	build := buildOptions{
		dataplaneOpener:  openDataplane,
		interfaceByIndex: net.InterfaceByIndex,
	}
	for _, apply := range buildOpts {
		apply(&build)
	}

	state := service.NewInMemoryRuntime()
	attachmentRuntime := service.AttachmentConfigRuntime(state)
	statsRuntime := service.StatsRuntime(state)
	eventRuntime := service.EventRuntime(state)
	var closer interface {
		Close() error
	}
	if options.Mode == ModeDataplane {
		runtime := NewDataplaneAttachmentRuntime(state, build.dataplaneOpener, build.interfaceByIndex)
		attachmentRuntime = runtime
		statsRuntime = runtime
		eventRuntime = runtime
		closer = runtime
	}

	composition := &Composition{
		Services: Services{
			Status: service.NewStatusServiceWithRuntime(service.RuntimeDeps{
				Attachments: attachmentRuntime,
				Ruleset:     state,
				Response:    state,
				Dispatch:    state,
			}),
			Ruleset:     service.NewRulesetService(state),
			Attachments: service.NewAttachmentService(attachmentRuntime),
			Response:    service.NewResponseService(state),
			Dispatch:    service.NewDispatchService(state),
			Stats:       service.NewStatsService(statsRuntime),
			Events:      service.NewEventService(eventRuntime),
		},
		mode:   options.Mode,
		closer: closer,
	}

	logrus.WithField("runtime_mode", composition.mode).Info("Built agent runtime")
	return composition, nil
}

func (c *Composition) Mode() Mode {
	return c.mode
}

func (c *Composition) Close() error {
	if c == nil || c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func openDataplane(options dataplane.Options) (DataplaneRuntime, error) {
	return dataplane.Open(options, dataplane.XSKConsumers{})
}
