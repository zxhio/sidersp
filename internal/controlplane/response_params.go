package controlplane

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
)

const (
	dnsDefaultTTLSeconds = 60
	dnsMaxTTLSeconds     = 2147483647
	tcpMaxSeqValue       = 4294967295
)

type integerResponseParam interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

type responseParamSchema struct {
	normalize func(action string, params map[string]interface{}) (map[string]interface{}, error)
}

var responseParamSchemas = map[string]responseParamSchema{
	"none":                  {normalize: forbidResponseParams},
	"alert":                 {normalize: forbidResponseParams},
	"tcp_reset":             {normalize: forbidResponseParams},
	"icmp_echo_reply":       {normalize: forbidResponseParams},
	"tcp_syn_ack":           {normalize: normalizeTCPSynAckResponseParams},
	"icmp_port_unreachable": {normalize: forbidResponseParams},
	"icmp_host_unreachable": {normalize: forbidResponseParams},
	"icmp_admin_prohibited": {normalize: forbidResponseParams},
	"udp_echo_reply":        {normalize: forbidResponseParams},
	"dns_sinkhole":          {normalize: normalizeDNSSinkholeResponseParams},
	"dns_refused":           {normalize: normalizeDNSRefusedResponseParams},
	"arp_reply":             {normalize: normalizeARPReplyResponseParams},
}

func validateResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	schema, ok := responseParamSchemas[action]
	if !ok {
		return nil, fmt.Errorf("response.action %q has no params schema", action)
	}
	return schema.normalize(action, params)
}

func forbidResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	if len(params) == 0 {
		return nil, nil
	}
	for key := range params {
		return nil, fmt.Errorf("response.params.%s is not allowed for action %s", key, action)
	}
	return nil, nil
}

func normalizeDNSSinkholeResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("response.params.family is required for action %s", action)
	}
	if err := rejectUnknownResponseParamKeys(action, params, "family", "answers_v4", "answers_v6", "ttl"); err != nil {
		return nil, err
	}

	family, err := validateFamilyResponseParam(params["family"])
	if err != nil {
		return nil, err
	}
	ttl := dnsDefaultTTLSeconds
	if rawTTL, ok := params["ttl"]; ok {
		normalizedTTL, err := validateTTLResponseParam(rawTTL)
		if err != nil {
			return nil, err
		}
		ttl = normalizedTTL
	}

	normalized := map[string]interface{}{
		"family": family,
		"ttl":    ttl,
	}

	if raw, ok := params["answers_v4"]; ok {
		answersV4, err := validateIPListResponseParam(raw, "answers_v4", true)
		if err != nil {
			return nil, err
		}
		normalized["answers_v4"] = answersV4
	}
	if raw, ok := params["answers_v6"]; ok {
		answersV6, err := validateIPListResponseParam(raw, "answers_v6", false)
		if err != nil {
			return nil, err
		}
		normalized["answers_v6"] = answersV6
	}

	switch family {
	case "ipv4":
		if _, ok := normalized["answers_v4"]; !ok {
			return nil, fmt.Errorf("response.params.answers_v4 is required when family is ipv4")
		}
	case "ipv6":
		if _, ok := normalized["answers_v6"]; !ok {
			return nil, fmt.Errorf("response.params.answers_v6 is required when family is ipv6")
		}
	case "dual":
		if _, ok := normalized["answers_v4"]; !ok {
			return nil, fmt.Errorf("response.params.answers_v4 is required when family is dual")
		}
		if _, ok := normalized["answers_v6"]; !ok {
			return nil, fmt.Errorf("response.params.answers_v6 is required when family is dual")
		}
	}

	return normalized, nil
}

func normalizeDNSRefusedResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	if err := rejectUnknownResponseParamKeys(action, params, "rcode"); err != nil {
		return nil, err
	}

	rcode := "refused"
	if raw, ok := params["rcode"]; ok {
		normalized, err := validateRCodeResponseParam(raw)
		if err != nil {
			return nil, err
		}
		rcode = normalized
	}

	return map[string]interface{}{
		"rcode": rcode,
	}, nil
}

func normalizeARPReplyResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	if len(params) == 0 {
		return nil, nil
	}
	if err := rejectUnknownResponseParamKeys(action, params, "hardware_addr", "sender_ipv4"); err != nil {
		return nil, err
	}

	normalized := make(map[string]interface{}, len(params))
	if raw, ok := params["hardware_addr"]; ok {
		hardwareAddr, err := validateMACResponseParam(raw)
		if err != nil {
			return nil, err
		}
		normalized["hardware_addr"] = hardwareAddr
	}
	if raw, ok := params["sender_ipv4"]; ok {
		senderIPv4, err := validateNamedIPv4ResponseParam("sender_ipv4", raw)
		if err != nil {
			return nil, err
		}
		normalized["sender_ipv4"] = senderIPv4
	}
	if len(normalized) == 0 {
		return nil, nil
	}
	return normalized, nil
}

func normalizeTCPSynAckResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	if err := rejectUnknownResponseParamKeys(action, params, "tcp_seq"); err != nil {
		return nil, err
	}

	tcpSeq := uint32(1)
	if raw, ok := params["tcp_seq"]; ok {
		normalized, err := validateTCPSeqResponseParam(raw)
		if err != nil {
			return nil, err
		}
		tcpSeq = normalized
	}

	return map[string]interface{}{
		"tcp_seq": tcpSeq,
	}, nil
}

func rejectUnknownResponseParamKeys(action string, params map[string]interface{}, allowedKeys ...string) error {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for key := range params {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("response.params.%s is not allowed for action %s", key, action)
		}
	}
	return nil
}

func validateFamilyResponseParam(value any) (string, error) {
	raw, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("response.params.family must be one of ipv4, ipv6, dual")
	}
	family := strings.ToLower(strings.TrimSpace(raw))
	switch family {
	case "ipv4", "ipv6", "dual":
		return family, nil
	default:
		return "", fmt.Errorf("response.params.family must be one of ipv4, ipv6, dual")
	}
}

func validateRCodeResponseParam(value any) (string, error) {
	raw, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("response.params.rcode must be one of refused, nxdomain, servfail")
	}
	rcode := strings.ToLower(strings.TrimSpace(raw))
	switch rcode {
	case "refused", "nxdomain", "servfail":
		return rcode, nil
	default:
		return "", fmt.Errorf("response.params.rcode must be one of refused, nxdomain, servfail")
	}
}

func validateNamedIPv4ResponseParam(field string, value any) (string, error) {
	raw, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("response.params.%s must be a single IPv4 address string", field)
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("response.params.%s must be a single IPv4 address string", field)
	}

	return addr.String(), nil
}

func validateIPListResponseParam(value any, field string, wantIPv4 bool) ([]string, error) {
	items, ok := responseParamStringList(value)
	if !ok || len(items) == 0 {
		return nil, responseParamIPListError(field, wantIPv4)
	}

	normalized := make([]string, 0, len(items))
	for _, item := range items {
		addr, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil {
			return nil, responseParamIPListError(field, wantIPv4)
		}
		if wantIPv4 && !addr.Is4() {
			return nil, responseParamIPListError(field, wantIPv4)
		}
		if !wantIPv4 && !addr.Is6() {
			return nil, responseParamIPListError(field, wantIPv4)
		}
		normalized = append(normalized, addr.String())
	}
	return normalized, nil
}

func responseParamStringList(value any) ([]string, bool) {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...), true
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			raw, ok := item.(string)
			if !ok {
				return nil, false
			}
			items = append(items, raw)
		}
		return items, true
	default:
		return nil, false
	}
}

func responseParamIPListError(field string, wantIPv4 bool) error {
	if wantIPv4 {
		return fmt.Errorf("response.params.%s must be a non-empty IPv4 address list", field)
	}
	return fmt.Errorf("response.params.%s must be a non-empty IPv6 address list", field)
}

func validateMACResponseParam(value any) (string, error) {
	raw, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("response.params.hardware_addr must be a 6-byte ethernet address string")
	}

	mac, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(mac) != 6 {
		return "", fmt.Errorf("response.params.hardware_addr must be a 6-byte ethernet address string")
	}
	return mac.String(), nil
}

func validateTTLResponseParam(value any) (int, error) {
	return normalizeAnyIntegerResponseParam(value, dnsMaxTTLSeconds, "response.params.ttl must be an integer in range 0..2147483647", func(v uint64) int {
		return int(v)
	})
}

func validateTCPSeqResponseParam(value any) (uint32, error) {
	return normalizeAnyIntegerResponseParam(value, tcpMaxSeqValue, "response.params.tcp_seq must be an integer in range 0..4294967295", func(v uint64) uint32 {
		return uint32(v)
	})
}

func normalizeAnyIntegerResponseParam[R any](value any, max uint64, errorText string, cast func(uint64) R) (R, error) {
	switch v := value.(type) {
	case int:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case int8:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case int16:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case int32:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case int64:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case uint:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case uint8:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case uint16:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case uint32:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case uint64:
		return normalizeIntegerResponseParam(v, max, errorText, cast)
	case float64:
		if math.Trunc(v) != v {
			var zero R
			return zero, fmt.Errorf("%s", errorText)
		}
		return normalizeIntegerResponseParam(int64(v), max, errorText, cast)
	default:
		var zero R
		return zero, fmt.Errorf("%s", errorText)
	}
}

func normalizeIntegerResponseParam[T integerResponseParam, R any](value T, max uint64, errorText string, cast func(uint64) R) (R, error) {
	if value < 0 || uint64(value) > max {
		var zero R
		return zero, fmt.Errorf("%s", errorText)
	}
	return cast(uint64(value)), nil
}
