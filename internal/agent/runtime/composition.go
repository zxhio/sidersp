package runtime

import (
	"fmt"

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
	Services  Services
	mode      Mode
	dataplane DataplaneRuntime
}

type DataplaneRuntime interface {
	service.DataplaneStatsReader
	service.DataplaneEventSource
	Close() error
}

type DataplaneOpener func(dataplane.Options) (DataplaneRuntime, error)

type buildOptions struct {
	dataplaneOpener DataplaneOpener
}

type BuildOption func(*buildOptions)

func WithDataplaneOpener(opener DataplaneOpener) BuildOption {
	return func(options *buildOptions) {
		options.dataplaneOpener = opener
	}
}

func NewComposition(options Options, buildOpts ...BuildOption) (*Composition, error) {
	options, err := options.normalize()
	if err != nil {
		return nil, err
	}

	build := buildOptions{
		dataplaneOpener: openDataplane,
	}
	for _, apply := range buildOpts {
		apply(&build)
	}

	state := service.NewInMemoryRuntime()
	statsRuntime := service.StatsRuntime(state)
	eventRuntime := service.EventRuntime(state)

	var dataplaneRuntime DataplaneRuntime
	if options.Mode == ModeDataplane {
		dataplaneOptions, err := newDataplaneOptions(options.Dataplane)
		if err != nil {
			return nil, err
		}
		dataplaneRuntime, err = build.dataplaneOpener(dataplaneOptions)
		if err != nil {
			return nil, fmt.Errorf("open dataplane runtime: %w", err)
		}
		adapter := service.NewDataplaneRuntimeAdapter(dataplaneRuntime, dataplaneRuntime)
		statsRuntime = adapter
		eventRuntime = adapter
	}

	composition := &Composition{
		Services: Services{
			Status:      service.NewStatusServiceWithRuntime(state.RuntimeDeps()),
			Ruleset:     service.NewRulesetService(state),
			Attachments: service.NewAttachmentService(state),
			Response:    service.NewResponseService(state),
			Dispatch:    service.NewDispatchService(state),
			Stats:       service.NewStatsService(statsRuntime),
			Events:      service.NewEventService(eventRuntime),
		},
		mode:      options.Mode,
		dataplane: dataplaneRuntime,
	}

	logrus.WithField("runtime_mode", composition.mode).Info("Built agent runtime")
	return composition, nil
}

func (c *Composition) Mode() Mode {
	return c.mode
}

func (c *Composition) Close() error {
	if c == nil || c.dataplane == nil {
		return nil
	}
	return c.dataplane.Close()
}

func newDataplaneOptions(options DataplaneOptions) (dataplane.Options, error) {
	if options.Interface == "" {
		return dataplane.Options{}, fmt.Errorf("dataplane interface is required")
	}
	return dataplane.Options{
		Interface:      options.Interface,
		IngressVerdict: "pass",
		XDPResponse: dataplane.XDPResponseOptions{
			VLANMode:       "preserve",
			FailureVerdict: "pass",
		},
	}, nil
}

func openDataplane(options dataplane.Options) (DataplaneRuntime, error) {
	return dataplane.Open(options, dataplane.XSKConsumers{})
}
