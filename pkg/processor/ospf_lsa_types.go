package processor

const (
	RouterLSAtypeV2         = 0x1
	NetworkLSAtypeV2        = 0x2
	SummaryLSANetworktypeV2 = 0x3
	SummaryLSAASBRtypeV2    = 0x4
	ASExternalLSAtypeV2     = 0x5
	NSSALSAtypeV2           = 0x7
)

// RouterV2 extends RouterLSAV2
type RouterV2 struct {
	Type     uint8
	LinkID   uint32
	LinkData uint32
	Metric   uint16
}

// RouterLSAV2 is the struct from RFC 2328  A.4.2.
type RouterLSAV2 struct {
	Flags   uint8
	Links   uint16
	Routers []RouterV2
}

type ASExternalLSAV2 struct {
	NetworkMask       uint32
	ExternalBit       uint8
	Metric            uint32
	ForwardingAddress uint32
	ExternalRouteTag  uint32
}

// NetworkLSAV2 is the struct from RFC 2328  A.4.3.
type NetworkLSAV2 struct {
	NetworkMask    uint32
	AttachedRouter []uint32
}

type SummaryLSAV2 struct {
	LinkStateID uint32
	NetworkMask uint32
	Metric      uint32
	Tos         uint8
	TosMetric   uint32
}
