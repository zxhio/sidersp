package types

type Stats struct {
	Ingress           IngressStats
	Parse             ParseStats
	Match             MatchStats
	KernelResponse    KernelResponseStats
	XSKRedirect       XSKRedirectStats
	UserspaceResponse UserspaceResponseStats
	Dispatch          DispatchStats
	Errors            ErrorStats
}

type IngressStats struct {
	Packets uint64
}

type ParseStats struct {
	OKPackets    uint64
	ErrorPackets uint64
}

type MatchStats struct {
	HitPackets  uint64
	MissPackets uint64
}

type KernelResponseStats struct {
	Packets         uint64
	XDPTXPackets    uint64
	RedirectPackets uint64
	ErrorPackets    uint64
}

type XSKRedirectStats struct {
	Packets      uint64
	ErrorPackets uint64
}

type UserspaceResponseStats struct {
	XSKRXPackets      uint64
	Packets           uint64
	XSKTXPackets      uint64
	AFPacketTXPackets uint64
	ErrorPackets      uint64
}

type DispatchStats struct {
	Packets        uint64
	QueuedPackets  uint64
	DroppedPackets uint64
	SentPackets    uint64
	ErrorPackets   uint64
}

type ErrorStats struct {
	XDPPackets uint64
	XSKPackets uint64
}
