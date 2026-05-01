package response

import "sidersp/internal/xsk"

const XSKMetadataSize = xsk.MetadataSize

type XSKMetadata = xsk.Metadata

func DecodeXSKMetadata(frame []byte) (XSKMetadata, []byte, error) {
	return xsk.DecodeMetadata(frame)
}
