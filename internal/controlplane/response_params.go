package controlplane

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
)

const dnsMaxTTLSeconds = 2147483647

type responseParamSchema struct {
	requiredKeys []string
	validators   map[string]func(any) (any, error)
}

var responseParamSchemas = map[string]responseParamSchema{
	"none":                  {},
	"alert":                 {},
	"tcp_reset":             {},
	"icmp_echo_reply":       {},
	"arp_reply":             {},
	"tcp_syn_ack":           {},
	"icmp_port_unreachable": {},
	"icmp_host_unreachable": {},
	"icmp_admin_prohibited": {},
	"udp_echo_reply":        {},
	"dns_refused":           {},
	"dns_sinkhole": {
		requiredKeys: []string{"address"},
		validators: map[string]func(any) (any, error){
			"address": validateIPv4ResponseParam,
			"ttl":     validateTTLResponseParam,
		},
	},
}

func validateResponseParams(action string, params map[string]interface{}) (map[string]interface{}, error) {
	schema, ok := responseParamSchemas[action]
	if !ok {
		return nil, fmt.Errorf("response.action %q has no params schema", action)
	}
	if len(params) == 0 {
		if len(schema.requiredKeys) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("response.params.%s is required for action %s", schema.requiredKeys[0], action)
	}

	normalized := make(map[string]interface{}, len(params))
	for key, value := range params {
		validator, ok := schema.validators[key]
		if !ok {
			return nil, fmt.Errorf("response.params.%s is not allowed for action %s", key, action)
		}
		normalizedValue, err := validator(value)
		if err != nil {
			return nil, err
		}
		normalized[key] = normalizedValue
	}

	for _, key := range schema.requiredKeys {
		if _, ok := normalized[key]; !ok {
			return nil, fmt.Errorf("response.params.%s is required for action %s", key, action)
		}
	}

	return normalized, nil
}

func validateIPv4ResponseParam(value any) (any, error) {
	raw, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("response.params.address must be a single IPv4 address string")
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("response.params.address must be a single IPv4 address string")
	}

	return addr.String(), nil
}

func validateTTLResponseParam(value any) (any, error) {
	switch v := value.(type) {
	case int:
		return normalizeTTLValue(int64(v))
	case int8:
		return normalizeTTLValue(int64(v))
	case int16:
		return normalizeTTLValue(int64(v))
	case int32:
		return normalizeTTLValue(int64(v))
	case int64:
		return normalizeTTLValue(v)
	case uint:
		return normalizeTTLValue(int64(v))
	case uint8:
		return normalizeTTLValue(int64(v))
	case uint16:
		return normalizeTTLValue(int64(v))
	case uint32:
		return normalizeTTLValue(int64(v))
	case float64:
		if math.Trunc(v) != v {
			return nil, fmt.Errorf("response.params.ttl must be an integer in range 0..2147483647")
		}
		return normalizeTTLValue(int64(v))
	default:
		return nil, fmt.Errorf("response.params.ttl must be an integer in range 0..2147483647")
	}
}

func normalizeTTLValue(value int64) (any, error) {
	if value < 0 || value > dnsMaxTTLSeconds {
		return nil, fmt.Errorf("response.params.ttl must be an integer in range 0..2147483647")
	}
	return int(value), nil
}
