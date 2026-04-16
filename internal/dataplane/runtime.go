package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"

	"sidersp/internal/rule"
)

const (
	maxRuleSlots     = 256
	statsLogInterval = 10 * time.Second

	condVLAN       = 1 << 0
	condSrcPrefix  = 1 << 1
	condDstPrefix  = 1 << 2
	condSrcPort    = 1 << 3
	condDstPort    = 1 << 4
	condHTTPMethod = 1 << 5
	condHTTP11     = 1 << 6
	condTCPSYN     = 1 << 7

	actionRST = 1
)

const (
	statRXPackets uint32 = iota
	statParseFailed
	statRuleCandidates
	statMatchedRules
	statRingbufDropped
)

var featureFlags = map[string]uint32{
	"TCP_SYN":     condTCPSYN,
	"HTTP_METHOD": condHTTPMethod,
	"HTTP_11":     condHTTP11,
}

type Runtime struct {
	objs    siderspObjects
	xdpLink link.Link
	iface   string
	opts    Options
}

type ruleEvent struct {
	TimestampNS uint64
	RuleID      uint32
	PktConds    uint32
	Action      uint32
	SIP         uint32
	DIP         uint32
	SPort       uint16
	DPort       uint16
	TCPFlags    uint8
	IPProto     uint8
	PayloadLen  uint16
}

type Options struct {
	Interface  string
	AttachMode string
}

type kernelStats struct {
	RXPackets      uint64
	ParseFailed    uint64
	RuleCandidates uint64
	MatchedRules   uint64
	RingbufDropped uint64
}

func Open(opts Options) (*Runtime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	var objs siderspObjects
	if err := loadSiderspObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dataplane objects: %w", err)
	}

	return &Runtime{
		objs:  objs,
		iface: opts.Interface,
		opts:  opts,
	}, nil
}

func (r *Runtime) Close() error {
	if r.xdpLink != nil {
		if err := r.xdpLink.Close(); err != nil {
			_ = r.objs.Close()
			return fmt.Errorf("detach xdp from %s: %w", r.iface, err)
		}
	}

	return r.objs.Close()
}

func (r *Runtime) RunEventStream(ctx context.Context) error {
	reader, err := ringbuf.NewReader(r.objs.EventRingbuf)
	if err != nil {
		return fmt.Errorf("open event ringbuf: %w", err)
	}

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	go r.logKernelStats(ctx, statsLogInterval)
	r.streamEvents(ctx, reader)

	return nil
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
				logrus.WithError(err).Warn("Fail to read kernel stats")
				continue
			}

			logrus.WithFields(stats.fields()).Info("Reported kernel stats")
		}
	}
}

func (r *Runtime) readKernelStats() (kernelStats, error) {
	rxPackets, err := readPerCPUCounter(r.objs.StatsMap, statRXPackets)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup rx_packets: %w", err)
	}
	parseFailed, err := readPerCPUCounter(r.objs.StatsMap, statParseFailed)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup parse_failed: %w", err)
	}
	ruleCandidates, err := readPerCPUCounter(r.objs.StatsMap, statRuleCandidates)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup rule_candidates: %w", err)
	}
	matchedRules, err := readPerCPUCounter(r.objs.StatsMap, statMatchedRules)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup matched_rules: %w", err)
	}
	ringbufDropped, err := readPerCPUCounter(r.objs.StatsMap, statRingbufDropped)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup ringbuf_dropped: %w", err)
	}

	return kernelStats{
		RXPackets:      rxPackets,
		ParseFailed:    parseFailed,
		RuleCandidates: ruleCandidates,
		MatchedRules:   matchedRules,
		RingbufDropped: ringbufDropped,
	}, nil
}

func (s kernelStats) fields() logrus.Fields {
	return logrus.Fields{
		"rx":    s.RXPackets,
		"parse": s.ParseFailed,
		"cand":  s.RuleCandidates,
		"match": s.MatchedRules,
		"drop":  s.RingbufDropped,
	}
}

func readPerCPUCounter(m *ebpf.Map, idx uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(idx, &values); err != nil {
		return 0, err
	}

	return sumPerCPUCounters(values), nil
}

func sumPerCPUCounters(values []uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func (r *Runtime) streamEvents(ctx context.Context, reader *ringbuf.Reader) {
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || err == ringbuf.ErrClosed {
				return
			}
			logrus.WithError(err).Error("Fail to read dataplane event")
			return
		}

		evt, err := decodeRuleEvent(record.RawSample)
		if err != nil {
			logrus.WithError(err).Error("Fail to decode dataplane event")
			continue
		}

		logrus.WithFields(logrus.Fields{
			"rule_id":     evt.RuleID,
			"action":      actionName(evt.Action),
			"sip":         ipv4String(evt.SIP),
			"dip":         ipv4String(evt.DIP),
			"sport":       evt.SPort,
			"dport":       evt.DPort,
			"proto":       evt.IPProto,
			"tcp_flags":   evt.TCPFlags,
			"pkt_conds":   conditionNames(evt.PktConds),
			"payload_len": evt.PayloadLen,
		}).Info("Matched rule")
	}
}

func (r *Runtime) ReplaceRules(set rule.RuleSet) error {
	snapshot, err := buildSnapshot(set)
	if err != nil {
		return err
	}

	r.logSnapshot(snapshot)

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
	if err := writeFeatureIndex(r.objs.FeatureIndexMap, snapshot.featureIndex); err != nil {
		return err
	}
	if err := r.attachOnce(); err != nil {
		return err
	}

	return nil
}

type compiledRule struct {
	slot           uint32
	rule           rule.Rule
	parsedPrefixes parsedRulePrefixes
	conditionMask  uint32
	action         uint32
}

type parsedRulePrefixes struct {
	src []netip.Prefix
	dst []netip.Prefix
}

type mapSnapshot struct {
	globalCfg      siderspGlobalCfg
	ruleIndex      map[uint32]siderspRuleMeta
	vlanIndex      map[uint16]siderspMaskT
	srcPortIndex   map[uint16]siderspMaskT
	dstPortIndex   map[uint16]siderspMaskT
	srcPrefixIndex map[siderspIpv4LpmKey]siderspMaskT
	dstPrefixIndex map[siderspIpv4LpmKey]siderspMaskT
	featureIndex   map[uint32]siderspMaskT
}

func buildSnapshot(set rule.RuleSet) (mapSnapshot, error) {
	if len(set.Rules) > maxRuleSlots {
		return mapSnapshot{}, fmt.Errorf("enabled rules %d exceed max slots %d", len(set.Rules), maxRuleSlots)
	}

	compiled := make([]compiledRule, 0, len(set.Rules))
	global := siderspGlobalCfg{}
	ruleIndex := make(map[uint32]siderspRuleMeta, len(set.Rules))
	parsedPrefixCache := make(map[string]netip.Prefix)

	for idx, r := range set.Rules {
		slot := uint32(idx)
		conditionMask, err := buildRequiredMask(r)
		if err != nil {
			return mapSnapshot{}, fmt.Errorf("rule %d: %w", idx, err)
		}

		parsedPrefixes, err := parseRulePrefixes(r, parsedPrefixCache)
		if err != nil {
			return mapSnapshot{}, fmt.Errorf("rule %d: %w", idx, err)
		}

		action, err := encodeAction(r.Response.Action)
		if err != nil {
			return mapSnapshot{}, fmt.Errorf("rule %d: %w", idx, err)
		}

		entry := compiledRule{
			slot:           slot,
			rule:           r,
			parsedPrefixes: parsedPrefixes,
			conditionMask:  conditionMask,
			action:         action,
		}
		compiled = append(compiled, entry)

		setMaskBit(&global.AllEnabledRules, slot)
		if len(r.Match.VLANs) == 0 {
			setMaskBit(&global.VlanOptionalRules, slot)
		}
		if len(r.Match.SrcPorts) == 0 {
			setMaskBit(&global.SrcPortOptionalRules, slot)
		}
		if len(r.Match.DstPorts) == 0 {
			setMaskBit(&global.DstPortOptionalRules, slot)
		}
		if len(r.Match.SrcPrefixes) == 0 {
			setMaskBit(&global.SrcPrefixOptionalRules, slot)
		}
		if len(r.Match.DstPrefixes) == 0 {
			setMaskBit(&global.DstPrefixOptionalRules, slot)
		}

		ruleIndex[slot] = siderspRuleMeta{
			RuleId:       uint32(r.ID),
			Priority:     uint32(r.Priority),
			Enabled:      1,
			RequiredMask: conditionMask,
			Action:       action,
		}
	}

	return mapSnapshot{
		globalCfg:      global,
		ruleIndex:      ruleIndex,
		vlanIndex:      buildU16Index(compiled, func(r rule.Rule) []int { return r.Match.VLANs }),
		srcPortIndex:   buildU16Index(compiled, func(r rule.Rule) []int { return r.Match.SrcPorts }),
		dstPortIndex:   buildU16Index(compiled, func(r rule.Rule) []int { return r.Match.DstPorts }),
		srcPrefixIndex: buildPrefixIndex(compiled, func(rule compiledRule) []netip.Prefix { return rule.parsedPrefixes.src }),
		dstPrefixIndex: buildPrefixIndex(compiled, func(rule compiledRule) []netip.Prefix { return rule.parsedPrefixes.dst }),
		featureIndex:   buildFeatureIndex(compiled),
	}, nil
}

func buildRequiredMask(rule rule.Rule) (uint32, error) {
	var mask uint32

	if len(rule.Match.VLANs) > 0 {
		mask |= condVLAN
	}
	if len(rule.Match.SrcPrefixes) > 0 {
		mask |= condSrcPrefix
	}
	if len(rule.Match.DstPrefixes) > 0 {
		mask |= condDstPrefix
	}
	if len(rule.Match.SrcPorts) > 0 {
		mask |= condSrcPort
	}
	if len(rule.Match.DstPorts) > 0 {
		mask |= condDstPort
	}

	for _, feature := range rule.Match.Features {
		bit, ok := featureFlags[strings.ToUpper(strings.TrimSpace(feature))]
		if !ok {
			return 0, fmt.Errorf("unsupported feature %q", feature)
		}
		mask |= bit
	}

	return mask, nil
}

func encodeAction(action string) (uint32, error) {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "RST":
		return actionRST, nil
	default:
		return 0, fmt.Errorf("unsupported action %q", action)
	}
}

func buildU16Index(rules []compiledRule, selector func(rule.Rule) []int) map[uint16]siderspMaskT {
	keys := make(map[uint16]struct{})
	for _, rule := range rules {
		for _, value := range selector(rule.rule) {
			keys[uint16(value)] = struct{}{}
		}
	}

	index := make(map[uint16]siderspMaskT, len(keys))
	for key := range keys {
		var mask siderspMaskT
		for _, rule := range rules {
			vals := selector(rule.rule)
			if len(vals) == 0 || containsInt(vals, int(key)) {
				setMaskBit(&mask, rule.slot)
			}
		}
		index[key] = mask
	}

	return index
}

func buildPrefixIndex(rules []compiledRule, selector func(compiledRule) []netip.Prefix) map[siderspIpv4LpmKey]siderspMaskT {
	unique := make(map[netip.Prefix]struct{})
	for _, rule := range rules {
		for _, prefix := range selector(rule) {
			unique[prefix] = struct{}{}
		}
	}

	prefixes := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		prefixes = append(prefixes, prefix)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if bits := a.Bits() - b.Bits(); bits != 0 {
			return bits
		}
		return strings.Compare(a.String(), b.String())
	})

	index := make(map[siderspIpv4LpmKey]siderspMaskT, len(prefixes))
	for _, prefix := range prefixes {
		var mask siderspMaskT
		for _, rule := range rules {
			candidates := selector(rule)
			if len(candidates) == 0 {
				setMaskBit(&mask, rule.slot)
				continue
			}
			for _, candidate := range candidates {
				if candidate.Contains(prefix.Addr()) {
					setMaskBit(&mask, rule.slot)
					break
				}
			}
		}
		index[makeLPMKey(prefix)] = mask
	}

	return index
}

func buildFeatureIndex(rules []compiledRule) map[uint32]siderspMaskT {
	index := make(map[uint32]siderspMaskT)
	for _, r := range rules {
		for _, bit := range []uint32{condHTTPMethod, condHTTP11, condTCPSYN} {
			if r.conditionMask&bit != 0 {
				mask := index[bit]
				setMaskBit(&mask, r.slot)
				index[bit] = mask
			}
		}
	}
	return index
}

func parseRulePrefixes(r rule.Rule, cache map[string]netip.Prefix) (parsedRulePrefixes, error) {
	src, err := parsePrefixes(r.Match.SrcPrefixes, cache)
	if err != nil {
		return parsedRulePrefixes{}, fmt.Errorf("parse src prefixes: %w", err)
	}

	dst, err := parsePrefixes(r.Match.DstPrefixes, cache)
	if err != nil {
		return parsedRulePrefixes{}, fmt.Errorf("parse dst prefixes: %w", err)
	}

	return parsedRulePrefixes{
		src: src,
		dst: dst,
	}, nil
}

func parsePrefixes(rawPrefixes []string, cache map[string]netip.Prefix) ([]netip.Prefix, error) {
	if len(rawPrefixes) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, 0, len(rawPrefixes))
	for _, raw := range rawPrefixes {
		prefix, ok := cache[raw]
		if !ok {
			parsed, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, err
			}
			prefix = parsed.Masked()
			cache[raw] = prefix
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func makeLPMKey(prefix netip.Prefix) siderspIpv4LpmKey {
	addr := prefix.Masked().Addr().As4()
	return siderspIpv4LpmKey{
		Prefixlen: uint32(prefix.Bits()),
		Addr:      binary.LittleEndian.Uint32(addr[:]),
	}
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func setMaskBit(mask *siderspMaskT, slot uint32) {
	group := slot / 64
	bit := slot % 64
	mask.Bits[group] |= 1 << bit
}

func (r *Runtime) resetMaps() error {
	var zeroRule siderspRuleMeta
	for slot := uint32(0); slot < maxRuleSlots; slot++ {
		if err := r.objs.RuleIndexMap.Put(slot, zeroRule); err != nil {
			return fmt.Errorf("reset rule_index_map slot %d: %w", slot, err)
		}
	}

	if err := clearMap(r.objs.VlanIndexMap); err != nil {
		return fmt.Errorf("reset vlan_index_map: %w", err)
	}
	if err := clearMap(r.objs.SrcPortIndexMap); err != nil {
		return fmt.Errorf("reset src_port_index_map: %w", err)
	}
	if err := clearMap(r.objs.DstPortIndexMap); err != nil {
		return fmt.Errorf("reset dst_port_index_map: %w", err)
	}
	if err := clearMap(r.objs.FeatureIndexMap); err != nil {
		return fmt.Errorf("reset feature_index_map: %w", err)
	}
	if err := clearMap(r.objs.SrcPrefixLpmMap); err != nil {
		return fmt.Errorf("reset src_prefix_lpm_map: %w", err)
	}
	if err := clearMap(r.objs.DstPrefixLpmMap); err != nil {
		return fmt.Errorf("reset dst_prefix_lpm_map: %w", err)
	}
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, siderspGlobalCfg{}); err != nil {
		return fmt.Errorf("reset global_cfg_map: %w", err)
	}

	return nil
}

func clearMap(m *ebpf.Map) error {
	var key any
	var value any
	iter := m.Iterate()
	var keys []any
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

func writeU16MaskMap(m *ebpf.Map, values map[uint16]siderspMaskT) error {
	for key, value := range values {
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

func writeGlobalConfig(m *ebpf.Map, cfg siderspGlobalCfg) error {
	var zero uint32
	if err := m.Put(zero, cfg); err != nil {
		return fmt.Errorf("write global_cfg_map: %w", err)
	}
	return nil
}

func writeFeatureIndex(m *ebpf.Map, values map[uint32]siderspMaskT) error {
	for key, value := range values {
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("write %s key %d: %w", m.String(), key, err)
		}
	}
	return nil
}

func (r *Runtime) logSnapshot(snapshot mapSnapshot) {
	r.logMask("all_enabled_rules", snapshot.globalCfg.AllEnabledRules)
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
		logrus.WithFields(logrus.Fields{
			"slot":          slot,
			"rule_id":       meta.RuleId,
			"priority":      meta.Priority,
			"enabled":       meta.Enabled,
			"action":        actionName(meta.Action),
			"required_mask": conditionNames(meta.RequiredMask),
		}).Info("Updated dataplane rule index")
	}

	r.logU16MaskIndex("vlan_index", snapshot.vlanIndex)
	r.logU16MaskIndex("src_port_index", snapshot.srcPortIndex)
	r.logU16MaskIndex("dst_port_index", snapshot.dstPortIndex)
	r.logPrefixMaskIndex("src_prefix_index", snapshot.srcPrefixIndex)
	r.logPrefixMaskIndex("dst_prefix_index", snapshot.dstPrefixIndex)
	r.logFeatureIndex("feature_index", snapshot.featureIndex)
}

func (r *Runtime) logU16MaskIndex(name string, index map[uint16]siderspMaskT) {
	keys := make([]int, 0, len(index))
	for key := range index {
		keys = append(keys, int(key))
	}
	slices.Sort(keys)

	if len(keys) == 0 {
		logrus.WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Info("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[uint16(key)]
		logrus.WithFields(logrus.Fields{
			"index": name,
			"key":   key,
			"slots": formatMaskSlots(mask),
			"bits":  formatMaskBits(mask),
		}).Info("Updated dataplane index")
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
		logrus.WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Info("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[key]
		logrus.WithFields(logrus.Fields{
			"index":  name,
			"prefix": formatLPMKey(key),
			"slots":  formatMaskSlots(mask),
			"bits":   formatMaskBits(mask),
		}).Info("Updated dataplane index")
	}
}

func (r *Runtime) logFeatureIndex(name string, index map[uint32]siderspMaskT) {
	if len(index) == 0 {
		logrus.WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Info("Updated dataplane index")
		return
	}

	keys := make([]uint32, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		mask := index[key]
		logrus.WithFields(logrus.Fields{
			"index": name,
			"cond":  conditionNames(key),
			"slots": formatMaskSlots(mask),
			"bits":  formatMaskBits(mask),
		}).Info("Updated dataplane index")
	}
}

func (r *Runtime) logMask(name string, mask siderspMaskT) {
	logrus.WithFields(logrus.Fields{
		"mask":  name,
		"slots": formatMaskSlots(mask),
		"bits":  formatMaskBits(mask),
	}).Info("Updated dataplane mask")
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

// attachOnce attaches the XDP program to the interface on the first call.
// Deferred until after ReplaceRules populates the maps so the XDP program
// never reads partially-initialized state.
func (r *Runtime) attachOnce() error {
	if r.xdpLink != nil {
		return nil
	}

	xdpLink, err := attachXDP(r.objs.XdpSidersp, r.opts)
	if err != nil {
		return err
	}

	r.xdpLink = xdpLink
	return nil
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

func decodeRuleEvent(raw []byte) (ruleEvent, error) {
	if len(raw) != 36 {
		return ruleEvent{}, fmt.Errorf("unexpected event size %d", len(raw))
	}

	return ruleEvent{
		TimestampNS: binary.LittleEndian.Uint64(raw[0:8]),
		RuleID:      binary.LittleEndian.Uint32(raw[8:12]),
		PktConds:    binary.LittleEndian.Uint32(raw[12:16]),
		Action:      binary.LittleEndian.Uint32(raw[16:20]),
		SIP:         binary.LittleEndian.Uint32(raw[20:24]),
		DIP:         binary.LittleEndian.Uint32(raw[24:28]),
		SPort:       binary.LittleEndian.Uint16(raw[28:30]),
		DPort:       binary.LittleEndian.Uint16(raw[30:32]),
		TCPFlags:    raw[32],
		IPProto:     raw[33],
		PayloadLen:  binary.LittleEndian.Uint16(raw[34:36]),
	}, nil
}

func ipv4String(v uint32) string {
	addr := [4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	return netip.AddrFrom4(addr).String()
}

func actionName(action uint32) string {
	switch action {
	case 1:
		return "RST"
	case 2:
		return "REPORT"
	case 0:
		return "NONE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}

func conditionNames(mask uint32) string {
	if mask == 0 {
		return "NONE"
	}

	names := make([]string, 0, 8)
	if mask&condVLAN != 0 {
		names = append(names, "VLAN")
	}
	if mask&condSrcPrefix != 0 {
		names = append(names, "SRC_PREFIX")
	}
	if mask&condDstPrefix != 0 {
		names = append(names, "DST_PREFIX")
	}
	if mask&condSrcPort != 0 {
		names = append(names, "SRC_PORT")
	}
	if mask&condDstPort != 0 {
		names = append(names, "DST_PORT")
	}
	if mask&condHTTPMethod != 0 {
		names = append(names, "HTTP_METHOD")
	}
	if mask&condHTTP11 != 0 {
		names = append(names, "HTTP_11")
	}
	if mask&condTCPSYN != 0 {
		names = append(names, "TCP_SYN")
	}

	return strings.Join(names, "|")
}
