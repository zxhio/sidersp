package runtime

import (
	"context"
	"net"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/service"
	"sidersp/internal/dataplane"
	"sidersp/internal/frameio"
	"sidersp/internal/frameio/afpacket"
	"sidersp/internal/rule"
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
	service.DataplaneEventSubscriber
	Attach() error
	RunXSK(context.Context) error
	ProgramID() (uint32, error)
	ReplaceRules(set rule.RuleSet) error
	ReplaceXDPResponse(options dataplane.XDPResponseOptions) error
	Close() error
}

type DataplaneOpener func(dataplane.Options, dataplane.XSKConsumers) (DataplaneRuntime, error)
type responseEgressWriterFactory func(string) (frameio.WriteCloser, error)

type interfaceLookup func(index int) (*net.Interface, error)

type buildOptions struct {
	dataplaneOpener      DataplaneOpener
	interfaceByIndex     interfaceLookup
	responseEgressWriter responseEgressWriterFactory
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

func WithResponseEgressWriterFactory(factory responseEgressWriterFactory) BuildOption {
	return func(options *buildOptions) {
		options.responseEgressWriter = factory
	}
}

func NewComposition(options Options, buildOpts ...BuildOption) (*Composition, error) {
	options, err := options.normalize()
	if err != nil {
		return nil, err
	}

	build := buildOptions{
		dataplaneOpener:      openDataplane,
		interfaceByIndex:     net.InterfaceByIndex,
		responseEgressWriter: newAFPacketWriter,
	}
	for _, apply := range buildOpts {
		apply(&build)
	}

	state := service.NewInMemoryRuntime()
	attachmentRuntime := service.AttachmentConfigRuntime(state)
	rulesetRuntime := service.RulesetRuntime(state)
	responseRuntime := service.ResponseConfigRuntime(state)
	dispatchRuntime := service.DispatchConfigRuntime(state)
	statsRuntime := service.StatsRuntime(state)
	eventRuntime := service.EventRuntime(state)
	var closer interface {
		Close() error
	}
	if options.Mode == ModeDataplane {
		runtime := NewDataplaneAttachmentRuntime(state, build.dataplaneOpener, build.interfaceByIndex)
		runtime.responseEgressWriter = build.responseEgressWriter
		attachmentRuntime = runtime
		rulesetRuntime = runtime
		responseRuntime = runtime
		dispatchRuntime = runtime
		statsRuntime = runtime
		eventRuntime = runtime
		closer = runtime
	}

	composition := &Composition{
		Services: Services{
			Status: service.NewStatusServiceWithRuntime(service.RuntimeDeps{
				Attachments: attachmentRuntime,
				Ruleset:     rulesetRuntime,
				Response:    responseRuntime,
				Dispatch:    dispatchRuntime,
			}),
			Ruleset:     service.NewRulesetService(rulesetRuntime),
			Attachments: service.NewAttachmentService(attachmentRuntime),
			Response:    service.NewResponseService(responseRuntime),
			Dispatch:    service.NewDispatchService(dispatchRuntime),
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

func openDataplane(options dataplane.Options, consumers dataplane.XSKConsumers) (DataplaneRuntime, error) {
	return dataplane.Open(options, consumers)
}

func newAFPacketWriter(ifname string) (frameio.WriteCloser, error) {
	return afpacket.New(ifname)
}
