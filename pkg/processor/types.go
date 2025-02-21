package processor

import (
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

// DD包的Interface MTU标志位
const (
	DDInterfaceMTUMismatch = 0x01
	DDInitialize           = 0x02
	DDMore                 = 0x04
	DDMaster               = 0x08
)

type OSPFPacket struct {
	Timestamp    time.Time
	SourceIP     net.IP
	DestIP       net.IP
	Version      uint8
	Type         layers.OSPFType //
	PacketLength uint16
	RouterID     net.IP
	AreaID       net.IP
	Checksum     uint16
	AuType       uint16

	// Hello包特有字段
	HelloFields *HelloFields

	// DD包特有字段
	DDFields *DDFields

	// 新增LSR字段
	LSRFields *LSRFields

	// 新增LSU字段
	LSUFields *LSUFields

	// 新增LSAck字段
	LSAckFields *LSAckFields
}

type HelloFields struct {
	NetworkMask            net.IPMask
	HelloInterval          uint16
	Options                uint32
	Priority               uint8
	DeadInterval           uint32
	DesignatedRouter       net.IP
	BackupDesignatedRouter net.IP
	Neighbors              []net.IP
}

type LSAHeader struct {
	Age               uint16
	Options           uint8
	Type              uint16
	LSID              net.IP
	AdvertisingRouter net.IP
	SequenceNum       uint32
	Checksum          uint16
	Length            uint16
}

// IsRouterLSA LSA类型检查方法
func (h *LSAHeader) IsRouterLSA() bool {
	return h.Type == 1
}

func (h *LSAHeader) IsNetworkLSA() bool {
	return h.Type == 2
}

func (h *LSAHeader) IsSummaryLSA() bool {
	return h.Type == 3 || h.Type == 4
}

func (h *LSAHeader) IsASExternalLSA() bool {
	return h.Type == 5
}

type DDFields struct {
	InterfaceMTU uint16
	Options      uint32
	Flags        uint16 // I、M、MS标志位
	DDSequence   uint32 // DD序列号
	LSAHeaders   []LSAHeader
}

// 检查是否是Master
func (d *DDFields) IsMaster() bool {
	return d.Flags&DDMaster != 0
}

// 检查是否设置了Initialize位
func (d *DDFields) IsInitialize() bool {
	return d.Flags&DDInitialize != 0
}

// 检查是否还有更多DD包
func (d *DDFields) HasMore() bool {
	return d.Flags&DDMore != 0
}

// HelloFields 的辅助方法
func (h *HelloFields) HasNeighbor(ip net.IP) bool {
	for _, neighbor := range h.Neighbors {
		if neighbor.Equal(ip) {
			return true
		}
	}
	return false
}

func (h *HelloFields) NeighborCount() int {
	return len(h.Neighbors)
}

func (h *HelloFields) IsDR(ip net.IP) bool {
	return h.DesignatedRouter.Equal(ip)
}

func (h *HelloFields) IsBDR(ip net.IP) bool {
	return h.BackupDesignatedRouter.Equal(ip)
}

type LSRFields struct {
	LSARequests []LSARequest
}

type LSARequest struct {
	LSType            uint16 // 改为uint16
	LSID              net.IP
	AdvertisingRouter net.IP
}

// LSU相关结构体定义
type LSUFields struct {
	NumOfLSAs uint32
	LSAs      []LSAFields
}

type LSAFields struct {
	Header  LSAHeader
	Content interface{}
}

type LSAckFields struct {
	LSAHeaders []LSAHeader
}

// OSPFPacket的辅助方法，用于更方便地访问DD包的标志位
func (p *OSPFPacket) IsDDMaster() bool {
	if p.DDFields != nil {
		return p.DDFields.IsMaster()
	}
	return false
}

func (p *OSPFPacket) IsDDInitialize() bool {
	if p.DDFields != nil {
		return p.DDFields.IsInitialize()
	}
	return false
}

func (p *OSPFPacket) HasDDMore() bool {
	if p.DDFields != nil {
		return p.DDFields.HasMore()
	}
	return false
}

// Uint32ToIP 辅助函数：将uint32转换为net.IP
func Uint32ToIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, i)
	return ip
}
