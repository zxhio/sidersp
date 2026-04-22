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

	"sidersp/internal/model"
	"sidersp/internal/rule"
)

type Runtime struct {
	objs    siderspObjects
	xdpLink link.Link
	iface   string
	opts    Options
}

type Options struct {
	Interface  string
	AttachMode string
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

// ReplaceRules rebuilds and writes the full rule snapshot to BPF maps.
//
// TODO: incremental updates — currently any rule change (create/update/delete/enable/disable)
// triggers a full rebuild of all indexes (rule_index, vlan/src_port/dst_port hash maps,
// src/dst prefix LPM tries, global_cfg). This is correct but costly at scale. Future work:
// stable ruleID→slot mapping, per-rule incremental index add/remove, unified delta path.
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
	if err := r.attachOnce(); err != nil {
		return err
	}

	return nil
}

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
	xdpTX, err := readPerCPUCounter(r.objs.StatsMap, statXDPTX)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup xdp_tx: %w", err)
	}
	xskTX, err := readPerCPUCounter(r.objs.StatsMap, statXskTX)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup xsk_tx: %w", err)
	}
	txFailed, err := readPerCPUCounter(r.objs.StatsMap, statTXFailed)
	if err != nil {
		return kernelStats{}, fmt.Errorf("lookup tx_failed: %w", err)
	}

	return kernelStats{
		RXPackets:      rxPackets,
		ParseFailed:    parseFailed,
		RuleCandidates: ruleCandidates,
		MatchedRules:   matchedRules,
		RingbufDropped: ringbufDropped,
		XDPTX:          xdpTX,
		XskTX:          xskTX,
		TXFailed:       txFailed,
	}, nil
}

func (r *Runtime) ReadStats() (model.DataplaneStats, error) {
	stats, err := r.readKernelStats()
	if err != nil {
		return model.DataplaneStats{}, err
	}

	return model.DataplaneStats{
		RXPackets:      stats.RXPackets,
		ParseFailed:    stats.ParseFailed,
		RuleCandidates: stats.RuleCandidates,
		MatchedRules:   stats.MatchedRules,
		RingbufDropped: stats.RingbufDropped,
		XDPTX:          stats.XDPTX,
		XskTX:          stats.XskTX,
		TXFailed:       stats.TXFailed,
	}, nil
}

// resetMaps clears BPF maps before ReplaceRules writes the next full snapshot.
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
	if err := writeGlobalConfig(r.objs.GlobalCfgMap, siderspGlobalCfg{}); err != nil {
		return fmt.Errorf("reset global_cfg_map: %w", err)
	}

	return nil
}

func (r *Runtime) logSnapshot(snapshot mapSnapshot) {
	logrus.WithFields(logrus.Fields{
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
		logrus.WithFields(logrus.Fields{
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
		logrus.WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Debug("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[uint16(key)]
		logrus.WithFields(logrus.Fields{
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
		logrus.WithFields(logrus.Fields{
			"index":   name,
			"entries": "[]",
		}).Debug("Updated dataplane index")
		return
	}

	for _, key := range keys {
		mask := index[key]
		logrus.WithFields(logrus.Fields{
			"index":  name,
			"prefix": formatLPMKey(key),
			"slots":  formatMaskSlots(mask),
			"bits":   formatMaskBits(mask),
		}).Debug("Updated dataplane index")
	}
}

func (r *Runtime) logMask(name string, mask siderspMaskT) {
	logrus.WithFields(logrus.Fields{
		"mask":  name,
		"slots": formatMaskSlots(mask),
		"bits":  formatMaskBits(mask),
	}).Debug("Updated dataplane mask")
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
