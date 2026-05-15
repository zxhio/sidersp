package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
)

func TestDataplaneAttachmentDryRunDoesNotOpen(t *testing.T) {
	opener := &recordingDataplaneOpener{}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.ValidateAttachment(context.Background(), types.Attachment{
		IfIndex: 3,
		Channels: types.AttachmentChannels{
			MaxRXQueueCount: 2,
		},
		XSK: types.AttachmentXSK{Enabled: true},
	})

	require.NoError(t, err)
	require.Equal(t, 3, got.IfIndex)
	require.Equal(t, "eth3", got.IfName)
	require.True(t, got.Enabled)
	require.True(t, got.XSK.Enabled)
	require.Equal(t, []int{0, 1}, got.XSK.Queues)
	require.Empty(t, opener.opens)

	items, err := runtime.ListAttachments(context.Background())
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestDataplaneAttachmentCreateOpensAndStoresState(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{{programID: 101}},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex:     3,
		AttachMode:  types.AttachModeGeneric,
		MissVerdict: types.MissVerdictDrop,
	})

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, "eth3", got.IfName)
	require.Equal(t, uint32(101), got.Runtime.ProgramID)
	require.Len(t, opener.opens, 1)
	require.Equal(t, "eth3", opener.opens[0].Interface)
	require.Equal(t, types.AttachModeGeneric, opener.opens[0].AttachMode)
	require.Equal(t, types.MissVerdictDrop, opener.opens[0].IngressVerdict)
	require.True(t, opener.runtimes[0].attached)
	require.Zero(t, opener.runtimes[0].xskRuns)

	stored, err := runtime.GetAttachment(context.Background(), 3)
	require.NoError(t, err)
	require.Equal(t, got, stored)
}

func TestDataplaneAttachmentCreateWithXSKMapsOptionsAndStartsRuntime(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID:  101,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 3,
		Channels: types.AttachmentChannels{
			RXQueueCount:    2,
			MaxRXQueueCount: 4,
		},
		XSK: types.AttachmentXSK{
			Enabled: true,
			Queues:  []int{1},
			UMEM: types.AttachmentUMEM{
				FrameSize:          4096,
				FrameCount:         8192,
				FillRingSize:       1024,
				CompletionRingSize: 512,
				RXRingSize:         256,
				TXRingSize:         128,
				TXFrameReserve:     64,
			},
		},
	})

	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskStarted)
	require.True(t, got.Enabled)
	require.Len(t, opener.opens, 1)
	options := opener.opens[0]
	require.Equal(t, "eth3", options.Interface)
	require.Equal(t, 2, options.CombinedChannels)
	require.True(t, options.XSK.Enabled)
	require.Equal(t, 3, options.XSK.IfIndex)
	require.Equal(t, []int{1}, options.XSK.Queues)
	require.Equal(t, 3, options.XSK.AFXDP.IfIndex)
	require.Equal(t, uint32(4096), options.XSK.AFXDP.FrameSize)
	require.Equal(t, uint32(8192), options.XSK.AFXDP.FrameCount)
	require.Equal(t, uint32(1024), options.XSK.AFXDP.FillRingSize)
	require.Equal(t, uint32(512), options.XSK.AFXDP.CompletionRingSize)
	require.Equal(t, uint32(256), options.XSK.AFXDP.RXRingSize)
	require.Equal(t, uint32(128), options.XSK.AFXDP.TXRingSize)
	require.Equal(t, uint32(64), options.XSK.AFXDP.TXFrameReserve)
	require.Equal(t, 1, fakeRuntime.xskRuns)

	require.NoError(t, runtime.Close())
	waitForChannel(t, fakeRuntime.xskDone)
	require.True(t, fakeRuntime.closed)
}

func TestDataplaneAttachmentCreateWithXSKEmptyQueuesUsesNormalizedQueues(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID:  101,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 4,
		Channels: types.AttachmentChannels{
			MaxRXQueueCount: 3,
		},
		XSK: types.AttachmentXSK{Enabled: true},
	})

	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskStarted)
	require.Equal(t, []int{0, 1, 2}, got.XSK.Queues)
	require.Equal(t, []int{0, 1, 2}, opener.opens[0].XSK.Queues)
	require.Equal(t, 3, opener.opens[0].CombinedChannels)

	require.NoError(t, runtime.Close())
	waitForChannel(t, fakeRuntime.xskDone)
}

func TestDataplaneAttachmentOpenFailureDoesNotStoreState(t *testing.T) {
	opener := &recordingDataplaneOpener{err: errors.New("open failed")}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 4})

	require.ErrorContains(t, err, "open failed")
	items, listErr := runtime.ListAttachments(context.Background())
	require.NoError(t, listErr)
	require.Empty(t, items)
	require.Len(t, opener.opens, 1)
}

func TestDataplaneAttachmentAttachFailureDoesNotStoreStateOrStartXSK(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		attachErr:  errors.New("attach failed"),
		xskStarted: make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 4,
		XSK:     types.AttachmentXSK{Enabled: true},
	})

	require.ErrorContains(t, err, "attach failed")
	items, listErr := runtime.ListAttachments(context.Background())
	require.NoError(t, listErr)
	require.Empty(t, items)
	require.True(t, fakeRuntime.closed)
	require.Zero(t, fakeRuntime.xskRuns)
}

func TestDataplaneAttachmentDuplicateDoesNotOpenAgain(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{{programID: 101}},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 5})
	require.NoError(t, err)

	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 5})

	require.ErrorAs(t, err, &types.ConflictError{})
	require.Len(t, opener.opens, 1)
}

func TestDataplaneAttachmentDisableClosesRuntimeAndKeepsAttachment(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 6})
	require.NoError(t, err)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 6, false)

	require.NoError(t, err)
	require.False(t, got.Enabled)
	require.Zero(t, got.Runtime.ProgramID)
	require.True(t, fakeRuntime.closed)

	stored, err := runtime.GetAttachment(context.Background(), 6)
	require.NoError(t, err)
	require.Equal(t, got, stored)
}

func TestDataplaneAttachmentReenableOpensRuntimeAgain(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 7})
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 7, false)
	require.NoError(t, err)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 7, true)

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, uint32(202), got.Runtime.ProgramID)
	require.True(t, first.closed)
	require.True(t, second.attached)
	require.Len(t, opener.opens, 2)
}

func TestDataplaneAttachmentReenableWithXSKStartsRuntimeAgain(t *testing.T) {
	first := &fakeDataplaneRuntime{
		programID:  101,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	second := &fakeDataplaneRuntime{
		programID:  202,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 7,
		XSK:     types.AttachmentXSK{Enabled: true},
	})
	require.NoError(t, err)
	waitForChannel(t, first.xskStarted)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 7, false)
	require.NoError(t, err)
	waitForChannel(t, first.xskDone)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 7, true)

	require.NoError(t, err)
	waitForChannel(t, second.xskStarted)
	require.True(t, got.Enabled)
	require.Equal(t, uint32(202), got.Runtime.ProgramID)
	require.True(t, first.closed)
	require.True(t, second.attached)
	require.Len(t, opener.opens, 2)
	require.True(t, opener.opens[1].XSK.Enabled)
	require.Equal(t, []int{0}, opener.opens[1].XSK.Queues)

	require.NoError(t, runtime.Close())
	waitForChannel(t, second.xskDone)
}

func TestDataplaneAttachmentCreateReplaysDesiredStateInOrder(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	var operations []string
	second := &fakeDataplaneRuntime{programID: 202, operations: &operations}
	applier := &recordingDispatchApplier{operations: &operations}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	runtime.dispatchApplier = applier
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 36})
	require.NoError(t, err)
	_, err = service.NewResponseService(runtime).ReplaceResponse(context.Background(), testResponseConfig(60, types.VLANModeAccess))
	require.NoError(t, err)
	_, err = service.NewDispatchService(runtime).ReplaceDispatch(context.Background(), testDispatchConfig(61, types.VLANModePreserve))
	require.NoError(t, err)
	_, err = service.NewRulesetService(runtime).ReplaceRuleset(context.Background(), testDataplaneRuleset(9, 9009), false)
	require.NoError(t, err)
	operations = nil

	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 37})

	require.NoError(t, err)
	require.Equal(t, []string{"response", "dispatch", "ruleset"}, operations)
	require.Len(t, second.appliedXDP, 1)
	require.Equal(t, 60, second.appliedXDP[0].EgressIfIndex)
	require.Len(t, applier.configs, 3)
	require.Equal(t, 61, applier.configs[len(applier.configs)-1].TargetIfIndex)
	require.Len(t, second.appliedRules, 1)
	require.Equal(t, 9009, second.appliedRules[0].Rules[0].ID)
}

func TestDataplaneAttachmentReenableReplaysDesiredState(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	applier := &recordingDispatchApplier{}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	runtime.dispatchApplier = applier
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 38})
	require.NoError(t, err)
	_, err = service.NewResponseService(runtime).ReplaceResponse(context.Background(), testResponseConfig(62, types.VLANModeAccess))
	require.NoError(t, err)
	_, err = service.NewDispatchService(runtime).ReplaceDispatch(context.Background(), testDispatchConfig(63, types.VLANModePreserve))
	require.NoError(t, err)
	_, err = service.NewRulesetService(runtime).ReplaceRuleset(context.Background(), testDataplaneRuleset(10, 10010), false)
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 38, false)
	require.NoError(t, err)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 38, true)

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, uint32(202), got.Runtime.ProgramID)
	require.Len(t, second.appliedXDP, 1)
	require.Equal(t, 62, second.appliedXDP[0].EgressIfIndex)
	require.Equal(t, 63, applier.configs[len(applier.configs)-1].TargetIfIndex)
	require.Len(t, second.appliedRules, 1)
	require.Equal(t, 10010, second.appliedRules[0].Rules[0].ID)
}

func TestDataplaneAttachmentDryRunDoesNotReplayDesiredState(t *testing.T) {
	opener := &recordingDataplaneOpener{}
	applier := &recordingDispatchApplier{}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	runtime.dispatchApplier = applier
	svc := service.NewAttachmentService(runtime)

	_, err := svc.CreateAttachment(context.Background(), types.Attachment{IfIndex: 39}, true)

	require.NoError(t, err)
	require.Empty(t, opener.opens)
	require.Empty(t, applier.configs)
}

func TestDataplaneAttachmentCreateReplayFailureClosesRuntimeAndDoesNotStore(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		xdpErr:    errors.New("response failed"),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 40})

	require.ErrorContains(t, err, "response failed")
	require.True(t, fakeRuntime.closed)
	_, err = runtime.GetAttachment(context.Background(), 40)
	require.ErrorAs(t, err, &types.NotFoundError{})
}

func TestDataplaneAttachmentReenableReplayFailureKeepsAttachmentDisabled(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{
		programID: 202,
		applyErr:  errors.New("ruleset failed"),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 41})
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 41, false)
	require.NoError(t, err)

	_, err = runtime.SetAttachmentEnabled(context.Background(), 41, true)

	require.ErrorContains(t, err, "ruleset failed")
	require.True(t, second.closed)
	stored, getErr := runtime.GetAttachment(context.Background(), 41)
	require.NoError(t, getErr)
	require.False(t, stored.Enabled)
	require.Zero(t, stored.Runtime.ProgramID)
}

func TestDataplaneAttachmentCreateWithoutRulesetAppliesEmptyRuleset(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 42})

	require.NoError(t, err)
	require.Len(t, fakeRuntime.appliedRules, 1)
	require.Empty(t, fakeRuntime.appliedRules[0].Rules)
}

func TestDataplaneAttachmentDeleteClosesRuntimeAndRemovesAttachment(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 8})
	require.NoError(t, err)

	err = runtime.DeleteAttachment(context.Background(), 8)

	require.NoError(t, err)
	require.True(t, fakeRuntime.closed)
	_, err = runtime.GetAttachment(context.Background(), 8)
	require.ErrorAs(t, err, &types.NotFoundError{})
}

func TestDataplaneAttachmentDisableWithXSKStopsRuntime(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID:  101,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 8,
		XSK:     types.AttachmentXSK{Enabled: true},
	})
	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskStarted)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 8, false)

	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskDone)
	require.False(t, got.Enabled)
	require.True(t, fakeRuntime.closed)
}

func TestDataplaneAttachmentDeleteWithXSKStopsRuntime(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID:  101,
		xskStarted: make(chan struct{}),
		xskDone:    make(chan struct{}),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 8,
		XSK:     types.AttachmentXSK{Enabled: true},
	})
	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskStarted)

	err = runtime.DeleteAttachment(context.Background(), 8)

	require.NoError(t, err)
	waitForChannel(t, fakeRuntime.xskDone)
	require.True(t, fakeRuntime.closed)
}

func TestDataplaneAttachmentCloseFailureReturnsErrorAndKeepsAttachmentEnabled(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		closeErr:  errors.New("close failed"),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 9})
	require.NoError(t, err)

	_, err = runtime.SetAttachmentEnabled(context.Background(), 9, false)

	require.ErrorContains(t, err, "close failed")
	stored, getErr := runtime.GetAttachment(context.Background(), 9)
	require.NoError(t, getErr)
	require.True(t, stored.Enabled)
	require.Equal(t, uint32(101), stored.Runtime.ProgramID)
}

func TestDataplaneAttachmentReadStatsAggregatesActiveRuntimes(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{
			{programID: 101, stats: model.DataplaneStats{
				RXPackets:             10,
				ParseOKPackets:        8,
				ParseFailed:           1,
				MatchedRules:          3,
				MatchMissPackets:      5,
				KernelResponsePackets: 2,
			}},
			{programID: 202, stats: model.DataplaneStats{
				RXPackets:             20,
				ParseOKPackets:        18,
				TXFailed:              2,
				MatchedRules:          4,
				MatchMissPackets:      6,
				KernelResponsePackets: 3,
			}},
		},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 10})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 11})
	require.NoError(t, err)

	got, err := runtime.ReadStats(context.Background())

	require.NoError(t, err)
	require.Equal(t, uint64(30), got.Ingress.Packets)
	require.Equal(t, uint64(26), got.Parse.OKPackets)
	require.Equal(t, uint64(1), got.Parse.ErrorPackets)
	require.Equal(t, uint64(7), got.Match.HitPackets)
	require.Equal(t, uint64(11), got.Match.MissPackets)
	require.Equal(t, uint64(5), got.KernelResponse.Packets)
	require.Equal(t, uint64(3), got.Errors.XDPPackets)
}

func TestDataplaneAttachmentSubscribeEventsMergesEnabledRuntimes(t *testing.T) {
	first := &fakeDataplaneRuntime{
		programID: 101,
		eventCh:   make(chan model.EventRecord, 1),
	}
	second := &fakeDataplaneRuntime{
		programID: 202,
		eventCh:   make(chan model.EventRecord, 1),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 30})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 31})
	require.NoError(t, err)

	events, err := runtime.SubscribeEvents(context.Background())
	require.NoError(t, err)
	first.eventCh <- testModelEvent(1001)
	second.eventCh <- testModelEvent(1002)

	got := []uint32{
		readRuntimeEvent(t, events).RuleID,
		readRuntimeEvent(t, events).RuleID,
	}
	require.ElementsMatch(t, []uint32{1001, 1002}, got)
}

func TestDataplaneAttachmentSubscribeEventsSkipsDisabledRuntimes(t *testing.T) {
	first := &fakeDataplaneRuntime{
		programID: 101,
		eventCh:   make(chan model.EventRecord, 1),
	}
	second := &fakeDataplaneRuntime{
		programID: 202,
		eventCh:   make(chan model.EventRecord, 1),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 32})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 33})
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 32, false)
	require.NoError(t, err)

	events, err := runtime.SubscribeEvents(context.Background())
	require.NoError(t, err)
	second.eventCh <- testModelEvent(1002)

	got := readRuntimeEvent(t, events)
	require.Equal(t, uint32(1002), got.RuleID)
}

func TestDataplaneAttachmentSubscribeEventsPropagatesRuntimeError(t *testing.T) {
	wantErr := errors.New("subscribe failed")
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		eventErr:  wantErr,
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 34})
	require.NoError(t, err)

	events, err := runtime.SubscribeEvents(context.Background())

	require.Nil(t, events)
	require.ErrorIs(t, err, wantErr)
}

func TestDataplaneAttachmentSubscribeEventsClosesOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		eventCh:   make(chan model.EventRecord),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 35})
	require.NoError(t, err)
	events, err := runtime.SubscribeEvents(ctx)
	require.NoError(t, err)

	cancel()

	select {
	case _, ok := <-events:
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event stream to close")
	}
}

func TestDataplaneRulesetDryRunDoesNotApplyOrStore(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 12})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)
	appliedBefore := len(fakeRuntime.appliedRules)

	got, err := svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(2, 2002), true)

	require.NoError(t, err)
	require.Equal(t, uint64(2), got.Version)
	require.Len(t, fakeRuntime.appliedRules, appliedBefore)
	stored, err := runtime.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Zero(t, stored.Version)
	require.Nil(t, stored.Rules)
}

func TestDataplaneRulesetReplaceAppliesAllEnabledAttachments(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 13})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 14})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)

	got, err := svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(3, 3003), false)

	require.NoError(t, err)
	require.Equal(t, uint64(3), got.Version)
	require.Len(t, first.appliedRules, 2)
	require.Len(t, second.appliedRules, 2)
	require.Equal(t, 3003, first.appliedRules[len(first.appliedRules)-1].Rules[0].ID)
	require.Equal(t, 3003, second.appliedRules[len(second.appliedRules)-1].Rules[0].ID)

	stored, err := runtime.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(3), stored.Version)
}

func TestDataplaneRulesetApplyFailureDoesNotStoreAndRollsBack(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 15})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 16})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)
	previous := testDataplaneRuleset(4, 4004)
	_, err = svc.ReplaceRuleset(context.Background(), previous, false)
	require.NoError(t, err)
	second.applyErr = errors.New("apply failed")

	_, err = svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(5, 5005), false)

	require.ErrorContains(t, err, "apply failed")
	stored, getErr := runtime.GetRuleset(context.Background())
	require.NoError(t, getErr)
	require.Equal(t, previous.Version, stored.Version)
	require.Equal(t, previous.Rules[0].RuleID, stored.Rules[0].RuleID)
	require.Len(t, first.appliedRules, 4)
	require.Equal(t, 4004, first.appliedRules[len(first.appliedRules)-1].Rules[0].ID)
	require.Len(t, second.appliedRules, 3)
	require.Equal(t, 5005, second.appliedRules[len(second.appliedRules)-1].Rules[0].ID)
}

func TestDataplaneRulesetClearAppliesEmptyRuleset(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 17})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)
	_, err = svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(6, 6006), false)
	require.NoError(t, err)

	err = svc.ClearRuleset(context.Background())

	require.NoError(t, err)
	require.Len(t, fakeRuntime.appliedRules, 3)
	require.Empty(t, fakeRuntime.appliedRules[len(fakeRuntime.appliedRules)-1].Rules)
	stored, err := runtime.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Zero(t, stored.Version)
	require.Nil(t, stored.Rules)
}

func TestDataplaneRulesetCreateAttachmentAppliesCurrentRuleset(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 18})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)
	_, err = svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(7, 7007), false)
	require.NoError(t, err)

	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 19})

	require.NoError(t, err)
	require.Len(t, second.appliedRules, 1)
	require.Equal(t, 7007, second.appliedRules[0].Rules[0].ID)
}

func TestDataplaneRulesetReenableAttachmentAppliesCurrentRuleset(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 20})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)
	_, err = svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(8, 8008), false)
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 20, false)
	require.NoError(t, err)

	_, err = runtime.SetAttachmentEnabled(context.Background(), 20, true)

	require.NoError(t, err)
	require.Len(t, second.appliedRules, 1)
	require.Equal(t, 8008, second.appliedRules[0].Rules[0].ID)
}

func TestDataplaneResponseReplaceAppliesAllEnabledAttachments(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 21})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 22})
	require.NoError(t, err)
	svc := service.NewResponseService(runtime)

	got, err := svc.ReplaceResponse(context.Background(), testResponseConfig(30, types.VLANModeAccess))

	require.NoError(t, err)
	require.Equal(t, 30, got.IfIndex)
	require.Equal(t, types.VLANModeAccess, got.VLANMode)
	require.Len(t, first.appliedXDP, 2)
	require.Len(t, second.appliedXDP, 2)
	require.Equal(t, 30, first.appliedXDP[len(first.appliedXDP)-1].EgressIfIndex)
	require.Equal(t, types.VLANModeAccess, first.appliedXDP[len(first.appliedXDP)-1].VLANMode)
	require.Equal(t, "pass", first.appliedXDP[len(first.appliedXDP)-1].FailureVerdict)

	stored, err := runtime.GetResponse(context.Background())
	require.NoError(t, err)
	require.Equal(t, got, stored)
	configured, err := runtime.ResponseConfigured(context.Background())
	require.NoError(t, err)
	require.True(t, configured)
}

func TestDataplaneResponseApplyFailureDoesNotStoreAndRollsBack(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 23})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 24})
	require.NoError(t, err)
	svc := service.NewResponseService(runtime)
	previous := testResponseConfig(40, types.VLANModePreserve)
	_, err = svc.ReplaceResponse(context.Background(), previous)
	require.NoError(t, err)
	second.xdpErr = errors.New("tx config failed")

	_, err = svc.ReplaceResponse(context.Background(), testResponseConfig(41, types.VLANModeAccess))

	require.ErrorContains(t, err, "tx config failed")
	stored, getErr := runtime.GetResponse(context.Background())
	require.NoError(t, getErr)
	require.Equal(t, previous, stored)
	require.Len(t, first.appliedXDP, 4)
	require.Equal(t, 40, first.appliedXDP[len(first.appliedXDP)-1].EgressIfIndex)
	require.Equal(t, types.VLANModePreserve, first.appliedXDP[len(first.appliedXDP)-1].VLANMode)
	require.Len(t, second.appliedXDP, 3)
	require.Equal(t, 41, second.appliedXDP[len(second.appliedXDP)-1].EgressIfIndex)
}

func TestDataplaneResponseClearAppliesDefaultConfig(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 25})
	require.NoError(t, err)
	svc := service.NewResponseService(runtime)
	_, err = svc.ReplaceResponse(context.Background(), testResponseConfig(50, types.VLANModeAccess))
	require.NoError(t, err)

	err = svc.ClearResponse(context.Background())

	require.NoError(t, err)
	require.Len(t, fakeRuntime.appliedXDP, 3)
	require.Zero(t, fakeRuntime.appliedXDP[len(fakeRuntime.appliedXDP)-1].EgressIfIndex)
	require.Equal(t, types.VLANModePreserve, fakeRuntime.appliedXDP[len(fakeRuntime.appliedXDP)-1].VLANMode)
	require.Equal(t, "pass", fakeRuntime.appliedXDP[len(fakeRuntime.appliedXDP)-1].FailureVerdict)
	stored, err := runtime.GetResponse(context.Background())
	require.NoError(t, err)
	require.Zero(t, stored.IfIndex)
	require.Equal(t, types.VLANModePreserve, stored.VLANMode)
	configured, err := runtime.ResponseConfigured(context.Background())
	require.NoError(t, err)
	require.False(t, configured)
}

func TestDataplaneResponseCreateAttachmentAppliesCurrentConfig(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 26})
	require.NoError(t, err)
	svc := service.NewResponseService(runtime)
	_, err = svc.ReplaceResponse(context.Background(), testResponseConfig(60, types.VLANModeAccess))
	require.NoError(t, err)

	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 27})

	require.NoError(t, err)
	require.Len(t, second.appliedXDP, 1)
	require.Equal(t, 60, second.appliedXDP[0].EgressIfIndex)
	require.Equal(t, types.VLANModeAccess, second.appliedXDP[0].VLANMode)
}

func TestDataplaneResponseReenableAttachmentAppliesCurrentConfig(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 28})
	require.NoError(t, err)
	svc := service.NewResponseService(runtime)
	_, err = svc.ReplaceResponse(context.Background(), testResponseConfig(70, types.VLANModeAccess))
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 28, false)
	require.NoError(t, err)

	_, err = runtime.SetAttachmentEnabled(context.Background(), 28, true)

	require.NoError(t, err)
	require.Len(t, second.appliedXDP, 1)
	require.Equal(t, 70, second.appliedXDP[0].EgressIfIndex)
	require.Equal(t, types.VLANModeAccess, second.appliedXDP[0].VLANMode)
}

func newTestDataplaneAttachmentRuntime(opener *recordingDataplaneOpener) *DataplaneAttachmentRuntime {
	return NewDataplaneAttachmentRuntime(service.NewInMemoryRuntime(), opener.open, func(index int) (*net.Interface, error) {
		return &net.Interface{Index: index, Name: "eth" + strconv.Itoa(index)}, nil
	})
}

func testDataplaneRuleset(version uint64, ruleID uint32) types.Ruleset {
	return types.Ruleset{
		Version: version,
		Rules: []types.Rule{
			{
				RuleID:   ruleID,
				Priority: 10,
				Match: types.RuleMatch{
					Protocol: "tcp",
				},
				Response: types.RuleResponse{Action: "tcp_reset"},
			},
		},
	}
}

func testResponseConfig(ifindex int, vlanMode string) types.ResponseConfig {
	return types.ResponseConfig{
		IfIndex:  ifindex,
		IfName:   "eth" + strconv.Itoa(ifindex),
		VLANMode: vlanMode,
	}
}

func testModelEvent(ruleID uint32) model.EventRecord {
	return model.EventRecord{
		ObservedAt: time.Unix(1710000000, 0).UTC(),
		RuleID:     ruleID,
		Action:     "tcp_reset",
		Verdict:    "xdp_tx",
		SIP:        "10.1.2.3",
		DIP:        "192.168.1.20",
		SPort:      52345,
		DPort:      80,
		IPProto:    6,
	}
}

func readRuntimeEvent(t *testing.T, events <-chan types.Event) types.Event {
	t.Helper()

	select {
	case item := <-events:
		return item
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for runtime event")
	}
	return types.Event{}
}

func waitForChannel(t *testing.T, ch <-chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel")
	}
}

type recordingDataplaneOpener struct {
	opens    []dataplane.Options
	next     []*fakeDataplaneRuntime
	runtimes []*fakeDataplaneRuntime
	err      error
}

func (o *recordingDataplaneOpener) open(options dataplane.Options) (DataplaneRuntime, error) {
	o.opens = append(o.opens, options)
	if o.err != nil {
		return nil, o.err
	}
	if len(o.next) == 0 {
		runtime := &fakeDataplaneRuntime{}
		o.runtimes = append(o.runtimes, runtime)
		return runtime, nil
	}
	next := o.next[0]
	o.next = o.next[1:]
	o.runtimes = append(o.runtimes, next)
	return next, nil
}
