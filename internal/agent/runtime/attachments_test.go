package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
)

func TestDataplaneAttachmentDryRunDoesNotOpen(t *testing.T) {
	opener := &recordingDataplaneOpener{}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.ValidateAttachment(context.Background(), types.Attachment{IfIndex: 3})

	require.NoError(t, err)
	require.Equal(t, 3, got.IfIndex)
	require.Equal(t, "eth3", got.IfName)
	require.True(t, got.Enabled)
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

	stored, err := runtime.GetAttachment(context.Background(), 3)
	require.NoError(t, err)
	require.Equal(t, got, stored)
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
			{programID: 101, stats: model.DataplaneStats{RXPackets: 10, ParseFailed: 1}},
			{programID: 202, stats: model.DataplaneStats{RXPackets: 20, TXFailed: 2}},
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
	require.Equal(t, uint64(3), got.Errors.XDPPackets)
}

func TestDataplaneRulesetDryRunDoesNotApplyOrStore(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 12})
	require.NoError(t, err)
	svc := service.NewRulesetService(runtime)

	got, err := svc.ReplaceRuleset(context.Background(), testDataplaneRuleset(2, 2002), true)

	require.NoError(t, err)
	require.Equal(t, uint64(2), got.Version)
	require.Empty(t, fakeRuntime.appliedRules)
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
	require.Len(t, first.appliedRules, 1)
	require.Len(t, second.appliedRules, 1)
	require.Equal(t, 3003, first.appliedRules[0].Rules[0].ID)
	require.Equal(t, 3003, second.appliedRules[0].Rules[0].ID)

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
	require.Len(t, first.appliedRules, 3)
	require.Equal(t, 4004, first.appliedRules[2].Rules[0].ID)
	require.Len(t, second.appliedRules, 2)
	require.Equal(t, 5005, second.appliedRules[1].Rules[0].ID)
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
	require.Len(t, fakeRuntime.appliedRules, 2)
	require.Empty(t, fakeRuntime.appliedRules[1].Rules)
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
