package response

import (
	"encoding/binary"
	"fmt"
)

const XSKMetadataSize = 8

// XSKMetadata mirrors BPF struct xsk_meta.
type XSKMetadata struct {
	RuleID   uint32
	Action   uint16
	Reserved uint16
}

func DecodeXSKMetadata(frame []byte) (XSKMetadata, []byte, error) {
	if len(frame) < XSKMetadataSize {
		return XSKMetadata{}, nil, fmt.Errorf("xsk frame too short: %d", len(frame))
	}

	meta := XSKMetadata{
		RuleID:   binary.LittleEndian.Uint32(frame[0:4]),
		Action:   binary.LittleEndian.Uint16(frame[4:6]),
		Reserved: binary.LittleEndian.Uint16(frame[6:8]),
	}
	return meta, frame[XSKMetadataSize:], nil
}
