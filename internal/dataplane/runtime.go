package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
	"sidersp/internal/model"
	"sidersp/internal/rule"
	"sidersp/internal/xsk"
)

type Runtime struct {
	objs        siderspObjects
	xdpLink     link.Link
	iface       string
	opts        Options
	xskRuntime  xskRuntime
	promiscSet  bool
	snapshot    mapSnapshot
	snapshotSet bool
	events      *eventBuffer
	eventMu     sync.Mutex
	eventSubs   map[uint64]chan model.EventRecord
	eventNextID uint64
	eventCancel context.CancelFunc
	eventErr    error
	eventClosed bool
	matchMu     sync.RWMutex
	matchCounts map[uint32]uint64
}

type Options struct {
	Interface        string
	AttachMode       string
	CombinedChannels int
	IngressVerdict   string
	XDPResponse      XDPResponseOptions
	XSK              xsk.Options
}

type XDPResponseOptions struct {
	EgressIfIndex  int
	VLANMode       string
	FailureVerdict string
}

type XSKConsumers struct {
	Response xsk.ResponseConsumer
	Analysis xsk.AnalysisSubmitter
}

type xskRuntime interface {
	Run(context.Context) error
	Close() error
}

func Open(opts Options, consumers XSKConsumers) (*Runtime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := configureInterfaceCombinedChannels(opts.Interface, opts.CombinedChannels); err != nil {
		return nil, err
	}

	var objs siderspObjects
	if err := loadSiderspObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dataplane objects: %w", err)
	}

	r := &Runtime{
		objs:        objs,
		iface:       opts.Interface,
		opts:        opts,
		events:      newEventBuffer(defaultEventBufferSize),
		matchCounts: make(map[uint32]uint64),
	}
	if err := r.writeXDPResponseConfig(opts.XDPResponse); err != nil {
		_ = r.objs.Close()
		return nil, err
	}
	if opts.XSK.Enabled {
		runtime, err := xsk.NewRuntime(opts.XSK, xsk.RuntimeDeps{
			Registrar: r,
			Consumers: xsk.Consumers{
				Response: consumers.Response,
				Analysis: consumers.Analysis,
			},
		})
		if err != nil {
			_ = r.objs.Close()
			return nil, err
		}
		r.xskRuntime = runtime
	}
	return r, nil
}

func (r *Runtime) Close() error {
	r.closeEventStream()

	var closeErr error
	if r.xskRuntime != nil {
		if err := r.xskRuntime.Close(); err != nil {
			closeErr = err
		}
		r.xskRuntime = nil
	}
	if r.xdpLink != nil {
		if err := r.xdpLink.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("detach xdp from %s: %w", r.iface, err)
		}
	}

	if r.promiscSet {
		if err := setInterfacePromisc(r.iface, false); err != nil {
			logs.App().WithError(err).WithField("interface", r.iface).Warn("Fail to restore interface promiscuous mode")
			if closeErr == nil {
				closeErr = fmt.Errorf("restore promiscuous mode on %s: %w", r.iface, err)
			}
		}
	}

	if err := r.objs.Close(); err != nil && closeErr == nil {
		closeErr = err
	}

	return closeErr
}

func (r *Runtime) RunXSK(ctx context.Context) error {
	if r.xskRuntime == nil {
		return nil
	}
	return r.xskRuntime.Run(ctx)
}

func (r *Runtime) RunEventStream(ctx context.Context) error {
	reader, err := ringbuf.NewReader(r.objs.EventRingbuf)
	if err != nil {
		return fmt.Errorf("open event ringbuf: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	if err := r.setEventStreamCancel(cancel); err != nil {
		cancel()
		_ = reader.Close()
		return err
	}

	return r.consumeEventReader(runCtx, cancel, reader)
}

func (r *Runtime) Attach() error {
	return r.attachOnce()
}

func (r *Runtime) ProgramID() (uint32, error) {
	info, err := r.objs.XdpSidersp.Info()
	if err != nil {
		return 0, fmt.Errorf("read xdp program info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, nil
	}
	return uint32(id), nil
}

func (r *Runtime) Events() []model.EventRecord {
	if r.events == nil {
		return nil
	}
	return r.events.list()
}

func (r *Runtime) SubscribeEvents(ctx context.Context) (<-chan model.EventRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	if r.eventClosed {
		return nil, fmt.Errorf("dataplane event stream is closed")
	}
	if r.eventErr != nil {
		return nil, fmt.Errorf("stream dataplane events: %w", r.eventErr)
	}
	if r.eventCancel == nil {
		if err := r.startEventStreamLocked(); err != nil {
			return nil, err
		}
	}

	return r.subscribeEventRecordsLocked(ctx), nil
}

func (r *Runtime) ReplaceXDPResponse(opts XDPResponseOptions) error {
	if err := r.writeXDPResponseConfig(opts); err != nil {
		return err
	}
	r.opts.XDPResponse = opts
	return nil
}

// ReplaceRules rebuilds the next rule snapshot and syncs only the changed BPF map entries.
// The first sync still does a full map reset/write. Later syncs keep the existing
// "transiently pass traffic during update" contract by clearing flow cache, zeroing
// global config, applying map deltas, and then publishing the final global config.
func (r *Runtime) ReplaceRules(set rule.RuleSet) error {
	snapshot, err := buildSnapshot(set, r.opts)
	if err != nil {
		return err
	}

	r.logSnapshot(snapshot)

	if err := r.applySnapshot(snapshot); err != nil {
		return err
	}

	if err := r.attachOnce(); err != nil {
		return err
	}

	return nil
}

func (r *Runtime) applySnapshot(snapshot mapSnapshot) error {
	if !r.snapshotSet {
		if err := r.writeFullSnapshot(snapshot); err != nil {
			return err
		}
	} else {
		if err := r.writeSnapshotDelta(r.snapshot, snapshot); err != nil {
			return err
		}
	}
	r.snapshot = snapshot
	r.snapshotSet = true
	return nil
}

func (r *Runtime) writeFullSnapshot(snapshot mapSnapshot) error {
	if err := r.resetMaps(); err != nil {
		return err
	}
	if err := writeRuleIndex(r.objs.RuleIndexMap, snapshot.ruleIndex); err != nil {
		return err
	}
	if err := writeU16MaskMap(r.objs.VlanIndexMap, snapshot.vlanIndex); err != nil {
		return err
	}
	if err := writeU16MaskMap(r.objs.SrcPortIndexMap, snapshot.srcPortIndex); err != nil {
		return err
	}
	if err := writeU16MaskMap(r.objs.DstPortIndexMap, snapshot.dstPortIndex); err != nil {
		return err
	}
	if err := writePrefixMaskMap(r.objs.SrcPrefixLpmMap, snapshot.srcPrefixIndex); err != nil {
		return err
	}
	if err := writePrefixMaskMap(r.objs.DstPrefixLpmMap, snapshot.dstPrefixIndex); err != nil {
		return err
	}
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, snapshot.globalCfg); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) writeSnapshotDelta(prev, next mapSnapshot) error {
	if err := clearFlowCacheMap(r.objs.FlowCacheMap); err != nil {
		return fmt.Errorf("clear flow_cache_map: %w", err)
	}
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, siderspGlobalCfg{}); err != nil {
		return fmt.Errorf("disable global_cfg_map during incremental sync: %w", err)
	}
	if err := writeRuleIndexDelta(r.objs.RuleIndexMap, prev.ruleIndex, next.ruleIndex); err != nil {
		return err
	}
	if err := writeU16MaskMapDelta(r.objs.VlanIndexMap, prev.vlanIndex, next.vlanIndex); err != nil {
		return err
	}
	if err := writeU16MaskMapDelta(r.objs.SrcPortIndexMap, prev.srcPortIndex, next.srcPortIndex); err != nil {
		return err
	}
	if err := writeU16MaskMapDelta(r.objs.DstPortIndexMap, prev.dstPortIndex, next.dstPortIndex); err != nil {
		return err
	}
	if err := writePrefixMaskMapDelta(r.objs.SrcPrefixLpmMap, prev.srcPrefixIndex, next.srcPrefixIndex); err != nil {
		return err
	}
	if err := writePrefixMaskMapDelta(r.objs.DstPrefixLpmMap, prev.dstPrefixIndex, next.dstPrefixIndex); err != nil {
		return err
	}
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, next.globalCfg); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) attachOnce() error {
	if r.xdpLink != nil {
		return nil
	}

	if err := r.configurePromisc(); err != nil {
		return err
	}

	xdpLink, err := attachXDP(r.objs.XdpSidersp, r.opts)
	if err != nil {
		if r.promiscSet {
			if restoreErr := setInterfacePromisc(r.iface, false); restoreErr != nil {
				logs.App().WithError(restoreErr).WithField("interface", r.iface).Warn("Fail to restore interface promiscuous mode")
			}
			r.promiscSet = false
		}
		return err
	}

	r.xdpLink = xdpLink
	return nil
}

func (r *Runtime) configurePromisc() error {
	enabled, err := interfacePromisc(r.iface)
	if err != nil {
		return fmt.Errorf("read promiscuous mode on %s: %w", r.iface, err)
	}
	if enabled {
		logs.App().WithField("interface", r.iface).Info("Interface promiscuous mode already enabled")
		return nil
	}

	if err := setInterfacePromisc(r.iface, true); err != nil {
		return fmt.Errorf("enable promiscuous mode on %s: %w", r.iface, err)
	}
	r.promiscSet = true
	logs.App().WithField("interface", r.iface).Info("Enabled interface promiscuous mode")
	return nil
}

func (r *Runtime) streamEvents(ctx context.Context, reader eventReader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || err == ringbuf.ErrClosed {
				return nil
			}
			return fmt.Errorf("read dataplane event: %w", err)
		}

		evt, err := decodeRuleEvent(record.RawSample)
		if err != nil {
			logs.App().WithError(err).Error("Fail to decode dataplane event")
			continue
		}
		item := newEventRecord(evt, time.Now().UTC())
		if r.events != nil {
			r.events.add(item)
		}
		r.publishEventRecord(item)

		r.matchMu.Lock()
		r.matchCounts[evt.RuleID]++
		r.matchMu.Unlock()

		r.logMatchedRule(evt)
	}
}

func (r *Runtime) logKernelStats(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := r.readKernelStats()
			if err != nil {
				logs.App().WithError(err).Warn("Fail to read kernel stats")
				continue
			}

			r.logKernelStatsSnapshot(stats)
		}
	}
}

func (r *Runtime) readKernelStats() (kernelStats, error) {
	var stats kernelStats
	reads := []struct {
		name string
		idx  uint32
		dst  *uint64
	}{
		{"ingress_packets", statIngressPackets, &stats.IngressPackets},
		{"parse_ok_packets", statParseOKPackets, &stats.ParseOKPackets},
		{"parse_error_packets", statParseErrorPackets, &stats.ParseErrorPackets},
		{"match_hit_packets", statMatchHitPackets, &stats.MatchHitPackets},
		{"match_miss_packets", statMatchMissPackets, &stats.MatchMissPackets},
		{"kernel_response_packets", statKernelResponsePackets, &stats.KernelResponsePackets},
		{"kernel_response_xdp_tx_packets", statKernelResponseXDPTXPackets, &stats.KernelResponseXDPTXPackets},
		{"kernel_response_redirect_packets", statKernelResponseRedirectPackets, &stats.KernelResponseRedirectPackets},
		{"kernel_response_error_packets", statKernelResponseErrorPackets, &stats.KernelResponseErrorPackets},
		{"xsk_redirect_packets", statXSKRedirectPackets, &stats.XSKRedirectPackets},
		{"xsk_redirect_error_packets", statXSKRedirectErrorPackets, &stats.XSKRedirectErrorPackets},
		{"event_dropped_packets", statEventDroppedPackets, &stats.EventDroppedPackets},
		{"diag_rule_candidates", statDiagRuleCandidates, &stats.DiagRuleCandidates},
		{"diag_redirect_failed", statDiagRedirectFailed, &stats.DiagRedirectFailed},
		{"diag_fib_lookup_failed", statDiagFibLookupFailed, &stats.DiagFibLookupFailed},
		{"diag_xsk_meta_failed", statDiagXSKMetaFailed, &stats.DiagXSKMetaFailed},
		{"diag_xsk_map_redirect_failed", statDiagXSKMapRedirectFailed, &stats.DiagXSKMapRedirectFailed},
	}

	for _, read := range reads {
		value, err := readPerCPUCounter(r.objs.StatsMap, read.idx)
		if err != nil {
			return kernelStats{}, fmt.Errorf("lookup %s: %w", read.name, err)
		}
		*read.dst = value
	}

	return stats, nil
}

func (r *Runtime) ReadStats() (model.DataplaneStats, error) {
	stats, err := r.readKernelStats()
	if err != nil {
		return model.DataplaneStats{}, err
	}
	r.matchMu.RLock()
	ruleMatches := make(map[uint32]uint64, len(r.matchCounts))
	for ruleID, matchedCount := range r.matchCounts {
		ruleMatches[ruleID] = matchedCount
	}
	r.matchMu.RUnlock()

	return model.DataplaneStats{
		RXPackets:             stats.IngressPackets,
		ParseOKPackets:        stats.ParseOKPackets,
		ParseFailed:           stats.ParseErrorPackets,
		MatchedRules:          stats.MatchHitPackets,
		MatchMissPackets:      stats.MatchMissPackets,
		KernelResponsePackets: stats.KernelResponsePackets,
		RuleMatches:           ruleMatches,
		RingbufDropped:        stats.EventDroppedPackets,
		XDPTX:                 stats.KernelResponseXDPTXPackets,
		TXFailed:              stats.KernelResponseErrorPackets,
		XskRedirected:         stats.XSKRedirectPackets,
		XskRedirectFailed:     stats.XSKRedirectErrorPackets,
		RedirectTX:            stats.KernelResponseRedirectPackets,
	}, nil
}

func (r *Runtime) ResetStats() error {
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("detect possible cpus: %w", err)
	}

	zeros := make([]uint64, possibleCPUs)
	for idx := uint32(0); idx < statCount; idx++ {
		if err := r.objs.StatsMap.Put(idx, zeros); err != nil {
			return fmt.Errorf("reset stats_map[%d]: %w", idx, err)
		}
	}

	r.matchMu.Lock()
	r.matchCounts = make(map[uint32]uint64)
	r.matchMu.Unlock()

	return nil
}

// resetMaps clears BPF maps before the first full snapshot write.
// During this transient window the BPF program sees empty config and passes
// traffic, which is acceptable for mirrored-traffic deployments.
func (r *Runtime) resetMaps() error {
	var zeroRule siderspRuleMeta
	for slot := uint32(0); slot < maxRuleSlots; slot++ {
		if err := r.objs.RuleIndexMap.Put(slot, zeroRule); err != nil {
			return fmt.Errorf("reset rule_index_map slot %d: %w", slot, err)
		}
	}

	if err := clearU16Map(r.objs.VlanIndexMap); err != nil {
		return fmt.Errorf("reset vlan_index_map: %w", err)
	}
	if err := clearU16Map(r.objs.SrcPortIndexMap); err != nil {
		return fmt.Errorf("reset src_port_index_map: %w", err)
	}
	if err := clearU16Map(r.objs.DstPortIndexMap); err != nil {
		return fmt.Errorf("reset dst_port_index_map: %w", err)
	}
	if err := clearPrefixMap(r.objs.SrcPrefixLpmMap); err != nil {
		return fmt.Errorf("reset src_prefix_lpm_map: %w", err)
	}
	if err := clearPrefixMap(r.objs.DstPrefixLpmMap); err != nil {
		return fmt.Errorf("reset dst_prefix_lpm_map: %w", err)
	}
	if err := clearFlowCacheMap(r.objs.FlowCacheMap); err != nil {
		return fmt.Errorf("reset flow_cache_map: %w", err)
	}
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, siderspGlobalCfg{}); err != nil {
		return fmt.Errorf("reset global_cfg_map: %w", err)
	}

	return nil
}

func (r *Runtime) logSnapshot(snapshot mapSnapshot) {
	logs.App().WithFields(logrus.Fields{
		"rules":              len(snapshot.ruleIndex),
		"vlan_entries":       len(snapshot.vlanIndex),
		"src_port_entries":   len(snapshot.srcPortIndex),
		"dst_port_entries":   len(snapshot.dstPortIndex),
		"src_prefix_entries": len(snapshot.srcPrefixIndex),
		"dst_prefix_entries": len(snapshot.dstPrefixIndex),
	}).Info("Updated dataplane rule snapshot")

	r.logMask("all_active_rules", snapshot.globalCfg.AllActiveRules)
	r.logMask("vlan_optional_rules", snapshot.globalCfg.VlanOptionalRules)
	r.logMask("src_port_optional_rules", snapshot.globalCfg.SrcPortOptionalRules)
	r.logMask("dst_port_optional_rules", snapshot.globalCfg.DstPortOptionalRules)
	r.logMask("src_prefix_optional_rules", snapshot.globalCfg.SrcPrefixOptionalRules)
	r.logMask("dst_prefix_optional_rules", snapshot.globalCfg.DstPrefixOptionalRules)

	slots := make([]uint32, 0, len(snapshot.ruleIndex))
	for slot := range snapshot.ruleIndex {
		slots = append(slots, slot)
	}
	slices.Sort(slots)

	for _, slot := range slots {
		meta := snapshot.ruleIndex[slot]
		logs.App().WithFields(logrus.Fields{
			"slot":          slot,
			"rule_id":       meta.RuleId,
			"action":        actionName(meta.Action),
			"required_mask": conditionNames(meta.RequiredMask),
		}).Debug("Updated dataplane rule index")
	}

	r.logU16MaskIndex("vlan_index", snapshot.vlanIndex)
	r.logU16MaskIndex("src_port_index", snapshot.srcPortIndex)
	r.logU16MaskIndex("dst_port_index", snapshot.dstPortIndex)
	r.logPrefixMaskIndex("src_prefix_index", snapshot.srcPrefixIndex)
	r.logPrefixMaskIndex("dst_prefix_index", snapshot.dstPrefixIndex)
}

func (r *Runtime) logU16MaskIndex(name string, index map[uint16]siderspMaskT) {
	keys := make([]int, 0, len(index))
	for key := range index {
		keys = append(keys, int(key))
	}
	slices.Sort(keys)

	if len(keys) == 0 {
		logs.App().WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Debug("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[uint16(key)]
		logs.App().WithFields(logrus.Fields{
			"index": name,
			"key":   key,
			"slots": formatMaskSlots(mask),
			"bits":  formatMaskBits(mask),
		}).Debug("Updated dataplane index")
	}
}

func (r *Runtime) logPrefixMaskIndex(name string, index map[siderspIpv4LpmKey]siderspMaskT) {
	keys := make([]siderspIpv4LpmKey, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b siderspIpv4LpmKey) int {
		if a.Prefixlen != b.Prefixlen {
			return int(a.Prefixlen) - int(b.Prefixlen)
		}
		if a.Addr < b.Addr {
			return -1
		}
		if a.Addr > b.Addr {
			return 1
		}
		return 0
	})

	if len(keys) == 0 {
		logs.App().WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Debug("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[key]
		logs.App().WithFields(logrus.Fields{
			"index":  name,
			"prefix": formatLPMKey(key),
			"slots":  formatMaskSlots(mask),
			"bits":   formatMaskBits(mask),
		}).Debug("Updated dataplane index")
	}
}

func (r *Runtime) logMask(name string, mask siderspMaskT) {
	logs.App().WithFields(logrus.Fields{
		"mask":  name,
		"slots": formatMaskSlots(mask),
		"bits":  formatMaskBits(mask),
	}).Debug("Updated dataplane mask")
}

func (r *Runtime) logMatchedRule(evt ruleEvent) {
	logs.Event().WithFields(logrus.Fields{
		"rule_id":   evt.RuleID,
		"action":    actionName(evt.Action),
		"sip":       ipv4String(evt.SIP),
		"dip":       ipv4String(evt.DIP),
		"sport":     evt.SPort,
		"dport":     evt.DPort,
		"proto":     evt.IPProto,
		"pkt_conds": conditionNames(evt.PktConds),
		"verdict":   evt.Verdict,
	}).Info("Matched rule")
}

func (r *Runtime) logKernelStatsSnapshot(stats kernelStats) {
	logs.Stats().WithFields(stats.fields()).Info("Reported kernel stats")
}

func attachXDP(prog *ebpf.Program, opts Options) (link.Link, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(opts.Interface))
	if err != nil {
		return nil, fmt.Errorf("lookup dataplane interface %q: %w", opts.Interface, err)
	}

	flags, err := parseAttachMode(opts.AttachMode)
	if err != nil {
		return nil, err
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp to %s: %w", iface.Name, err)
	}

	return xdpLink, nil
}

func parseAttachMode(raw string) (link.XDPAttachFlags, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "driver", "drv", "native":
		return link.XDPDriverMode, nil
	case "", "generic", "skb":
		return link.XDPGenericMode, nil
	case "offload", "hw":
		return link.XDPOffloadMode, nil
	default:
		return 0, fmt.Errorf("unsupported dataplane.attach_mode %q", raw)
	}
}

func setMaskBit(mask *siderspMaskT, slot uint32) {
	group := slot / 64
	bit := slot % 64
	mask.Bits[group] |= 1 << bit
}

func clearU16Map(m *ebpf.Map) error {
	var key uint16
	var value siderspMaskT
	iter := m.Iterate()
	var keys []uint16
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func clearU32Map(m *ebpf.Map) error {
	var key uint32
	var value siderspMaskT
	iter := m.Iterate()
	var keys []uint32
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func clearPrefixMap(m *ebpf.Map) error {
	var key siderspIpv4LpmKey
	var value siderspMaskT
	iter := m.Iterate()
	var keys []siderspIpv4LpmKey
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func clearFlowCacheMap(m *ebpf.Map) error {
	var key siderspFlowCacheKey
	var value siderspFlowCacheEntry
	iter := m.Iterate()
	var keys []siderspFlowCacheKey
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func writeRuleIndex(m *ebpf.Map, values map[uint32]siderspRuleMeta) error {
	for slot, value := range values {
		if err := m.Put(slot, value); err != nil {
			return fmt.Errorf("write rule_index_map slot %d: %w", slot, err)
		}
	}
	return nil
}

func writeRuleIndexDelta(m *ebpf.Map, prev, next map[uint32]siderspRuleMeta) error {
	clears, writes := diffRuleIndex(prev, next)
	var zero siderspRuleMeta
	for _, slot := range clears {
		if err := m.Put(slot, zero); err != nil {
			return fmt.Errorf("clear rule_index_map slot %d: %w", slot, err)
		}
	}
	for slot, value := range writes {
		if err := m.Put(slot, value); err != nil {
			return fmt.Errorf("write rule_index_map slot %d: %w", slot, err)
		}
	}
	return nil
}

func writeU16MaskMap(m *ebpf.Map, values map[uint16]siderspMaskT) error {
	for key, value := range values {
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("write %s key %d: %w", m.String(), key, err)
		}
	}
	return nil
}

func writeU16MaskMapDelta(m *ebpf.Map, prev, next map[uint16]siderspMaskT) error {
	deletes, writes := diffU16MaskMap(prev, next)
	for _, key := range deletes {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("delete %s key %d: %w", m.String(), key, err)
		}
	}
	for key, value := range writes {
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("write %s key %d: %w", m.String(), key, err)
		}
	}
	return nil
}

func writePrefixMaskMap(m *ebpf.Map, values map[siderspIpv4LpmKey]siderspMaskT) error {
	for key, value := range values {
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("write %s prefix %d/%08x: %w", m.String(), key.Prefixlen, key.Addr, err)
		}
	}
	return nil
}

func writePrefixMaskMapDelta(m *ebpf.Map, prev, next map[siderspIpv4LpmKey]siderspMaskT) error {
	deletes, writes := diffPrefixMaskMap(prev, next)
	for _, key := range deletes {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("delete %s prefix %d/%08x: %w", m.String(), key.Prefixlen, key.Addr, err)
		}
	}
	for key, value := range writes {
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("write %s prefix %d/%08x: %w", m.String(), key.Prefixlen, key.Addr, err)
		}
	}
	return nil
}

func diffRuleIndex(prev, next map[uint32]siderspRuleMeta) ([]uint32, map[uint32]siderspRuleMeta) {
	clears := make([]uint32, 0)
	writes := make(map[uint32]siderspRuleMeta)

	for slot, value := range prev {
		nextValue, ok := next[slot]
		if ok && nextValue == value {
			continue
		}
		if !ok {
			clears = append(clears, slot)
		}
	}
	for slot, value := range next {
		prevValue, ok := prev[slot]
		if ok && prevValue == value {
			continue
		}
		writes[slot] = value
	}

	slices.Sort(clears)
	return clears, writes
}

func diffU16MaskMap(prev, next map[uint16]siderspMaskT) ([]uint16, map[uint16]siderspMaskT) {
	deletes := make([]uint16, 0)
	writes := make(map[uint16]siderspMaskT)

	for key, value := range prev {
		nextValue, ok := next[key]
		if ok && nextValue == value {
			continue
		}
		if !ok {
			deletes = append(deletes, key)
		}
	}
	for key, value := range next {
		prevValue, ok := prev[key]
		if ok && prevValue == value {
			continue
		}
		writes[key] = value
	}

	slices.Sort(deletes)
	return deletes, writes
}

func diffPrefixMaskMap(prev, next map[siderspIpv4LpmKey]siderspMaskT) ([]siderspIpv4LpmKey, map[siderspIpv4LpmKey]siderspMaskT) {
	deletes := make([]siderspIpv4LpmKey, 0)
	writes := make(map[siderspIpv4LpmKey]siderspMaskT)

	for key, value := range prev {
		nextValue, ok := next[key]
		if ok && nextValue == value {
			continue
		}
		if !ok {
			deletes = append(deletes, key)
		}
	}
	for key, value := range next {
		prevValue, ok := prev[key]
		if ok && prevValue == value {
			continue
		}
		writes[key] = value
	}

	slices.SortFunc(deletes, func(a, b siderspIpv4LpmKey) int {
		if a.Prefixlen != b.Prefixlen {
			return int(a.Prefixlen) - int(b.Prefixlen)
		}
		if a.Addr < b.Addr {
			return -1
		}
		if a.Addr > b.Addr {
			return 1
		}
		return 0
	})
	return deletes, writes
}

func writeGlobalConfig(m *ebpf.Map, cfg siderspGlobalCfg) error {
	var zero uint32
	if err := m.Put(zero, cfg); err != nil {
		return fmt.Errorf("write global_cfg_map: %w", err)
	}
	return nil
}

func formatMaskSlots(mask siderspMaskT) string {
	slots := make([]string, 0, maxRuleSlots)
	for group, word := range mask.Bits {
		if word == 0 {
			continue
		}
		for bit := 0; bit < 64; bit++ {
			if word&(1<<bit) == 0 {
				continue
			}
			slot := group*64 + bit
			slots = append(slots, fmt.Sprintf("%d", slot))
		}
	}
	if len(slots) == 0 {
		return "[]"
	}
	return "[" + strings.Join(slots, ",") + "]"
}

func formatMaskBits(mask siderspMaskT) string {
	words := make([]string, 0, len(mask.Bits))
	for _, word := range mask.Bits {
		words = append(words, fmt.Sprintf("0x%016x", word))
	}
	return "[" + strings.Join(words, ",") + "]"
}

func formatLPMKey(key siderspIpv4LpmKey) string {
	var addr [4]byte
	binary.LittleEndian.PutUint32(addr[:], key.Addr)
	return fmt.Sprintf("%s/%d", netip.AddrFrom4(addr).String(), key.Prefixlen)
}
