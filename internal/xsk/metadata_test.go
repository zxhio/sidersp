package xsk

import "testing"

func TestDecodeMetadata(t *testing.T) {
	t.Parallel()

	frame := []byte{
		0xe9, 0x03, 0x00, 0x00,
		0x03, 0x00,
		0x07, 0x00,
		0xaa, 0xbb, 0xcc,
	}

	meta, payload, err := DecodeMetadata(frame)
	if err != nil {
		t.Fatalf("DecodeMetadata() error = %v", err)
	}
	if meta.RuleID != 1001 || meta.Action != 3 || meta.Reserved != 7 {
		t.Fatalf("DecodeMetadata() meta = %+v, want rule=1001 action=3 reserved=7", meta)
	}
	if string(payload) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("DecodeMetadata() payload = %v, want [aa bb cc]", payload)
	}
}
