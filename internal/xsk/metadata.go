package xsk

import (
	"encoding/binary"
	"fmt"
)

const MetadataSize = 8

// Metadata mirrors BPF struct xsk_meta.
type Metadata struct {
	RuleID   uint32
	Action   uint16
	Reserved uint16
}

type Envelope struct {
	QueueID  int
	Metadata Metadata
	Frame    []byte
}

func DecodeMetadata(frame []byte) (Metadata, []byte, error) {
	if len(frame) < MetadataSize {
		return Metadata{}, nil, fmt.Errorf("xsk frame too short: %d", len(frame))
	}

	meta := Metadata{
		RuleID:   binary.LittleEndian.Uint32(frame[0:4]),
		Action:   binary.LittleEndian.Uint16(frame[4:6]),
		Reserved: binary.LittleEndian.Uint16(frame[6:8]),
	}
	return meta, frame[MetadataSize:], nil
}
