package dataplane

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"sidersp/internal/rule"
)

type compiledRule struct {
	slot           uint32
	rule           rule.Rule
	parsedPrefixes parsedRulePrefixes
	conditionMask  uint32
	action         uint16
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
}

func buildSnapshot(set rule.RuleSet, opts Options) (mapSnapshot, error) {
	if len(set.Rules) > maxRuleSlots {
		return mapSnapshot{}, fmt.Errorf("enabled rules %d exceed max slots %d", len(set.Rules), maxRuleSlots)
	}

	compiled := make([]compiledRule, 0, len(set.Rules))
	global := siderspGlobalCfg{
		IngressVerdict: ingressFailureVerdict(opts.IngressVerdict),
	}
	ruleIndex := make(map[uint32]siderspRuleMeta, len(set.Rules))
	parsedPrefixCache := make(map[string]netip.Prefix)

	// Sort rules by ascending priority number (highest priority = lowest number).
	// This ensures slot order reflects priority, enabling first-match-early-exit
	// in the BPF data plane.
	slices.SortFunc(set.Rules, func(a, b rule.Rule) int {
		if a.Priority != b.Priority {
			return cmp.Compare(a.Priority, b.Priority)
		}
		return cmp.Compare(a.ID, b.ID)
	})

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

		setMaskBit(&global.AllActiveRules, slot)
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
			RequiredMask: conditionMask,
			Action:       action,
			Flags:        0,
		}
	}

	return mapSnapshot{
		globalCfg:      global,
		ruleIndex:      ruleIndex,
		vlanIndex:      buildU16Index(compiled, 0xffff, func(r rule.Rule) []int { return r.Match.VLANs }),
		srcPortIndex:   buildU16Index(compiled, 0, func(r rule.Rule) []int { return r.Match.SrcPorts }),
		dstPortIndex:   buildU16Index(compiled, 0, func(r rule.Rule) []int { return r.Match.DstPorts }),
		srcPrefixIndex: buildPrefixIndex(compiled, func(rule compiledRule) []netip.Prefix { return rule.parsedPrefixes.src }),
		dstPrefixIndex: buildPrefixIndex(compiled, func(rule compiledRule) []netip.Prefix { return rule.parsedPrefixes.dst }),
	}, nil
}

func buildRequiredMask(rule rule.Rule) (uint32, error) {
	var mask uint32

	switch strings.ToLower(strings.TrimSpace(rule.Match.Protocol)) {
	case "tcp":
		mask |= condProtoTCP
	case "udp":
		mask |= condProtoUDP
	case "icmp":
		mask |= condProtoICMP
	case "arp":
		mask |= condProtoARP
	case "":
	default:
		return 0, fmt.Errorf("unsupported protocol %q", rule.Match.Protocol)
	}

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

	for name, bit := range tcpFlagBits {
		var value *bool
		switch name {
		case "SYN":
			value = rule.Match.TCPFlags.SYN
		case "ACK":
			value = rule.Match.TCPFlags.ACK
		case "RST":
			value = rule.Match.TCPFlags.RST
		case "FIN":
			value = rule.Match.TCPFlags.FIN
		case "PSH":
			value = rule.Match.TCPFlags.PSH
		}
		if value == nil {
			continue
		}
		if !*value {
			return 0, fmt.Errorf("negative tcp_flags.%s not supported", strings.ToLower(name))
		}
		mask |= bit
	}

	if rule.Match.ICMP != nil {
		switch strings.ToLower(strings.TrimSpace(rule.Match.ICMP.Type)) {
		case "echo_request":
			mask |= condICMPEchoRequest
		case "echo_reply":
			mask |= condICMPEchoReply
		default:
			return 0, fmt.Errorf("unsupported icmp type %q", rule.Match.ICMP.Type)
		}
	}

	if rule.Match.ARP != nil {
		switch strings.ToLower(strings.TrimSpace(rule.Match.ARP.Operation)) {
		case "request":
			mask |= condARPRequest
		case "reply":
			mask |= condARPReply
		default:
			return 0, fmt.Errorf("unsupported arp operation %q", rule.Match.ARP.Operation)
		}
	}

	return mask, nil
}

func encodeAction(action string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "none":
		return actionNone, nil
	case "alert":
		return actionAlert, nil
	case "tcp_reset":
		return actionTCPReset, nil
	case "icmp_echo_reply":
		return actionICMPEchoReply, nil
	case "arp_reply":
		return actionARPReply, nil
	case "tcp_syn_ack":
		return actionTCPSynAck, nil
	default:
		return 0, fmt.Errorf("unsupported action %q", action)
	}
}

func buildU16Index(rules []compiledRule, sentinel uint16, selector func(rule.Rule) []int) map[uint16]siderspMaskT {
	keys := make(map[uint16]struct{})
	for _, rule := range rules {
		for _, value := range selector(rule.rule) {
			keys[uint16(value)] = struct{}{}
		}
	}

	// Ensure the sentinel entry exists so the BPF side can always do a lookup
	// without checking whether the field is present.  When the packet's field
	// equals the sentinel value (0 for ports, VLAN_ID_NONE for VLAN), this
	// entry maps to the optional-rules mask.
	keys[sentinel] = struct{}{}

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

// makeLPMKey constructs an LPM trie key from an IPv4 prefix.
//
// Byte-order contract: binary.LittleEndian.Uint32 reinterprets the 4-byte
// network-order address as a little-endian uint32. On little-endian hosts
// (where this program runs), the resulting in-memory bytes match the __be32
// layout that the BPF LPM lookup uses. This is correct because both Go and
// BPF run on the same host. Do NOT use binary.BigEndian here.
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
