package processor

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

// DD包的Interface MTU标志位
const (
	DDInterfaceMTUMismatch = 0x01
	DDInitialize           = 0x02
	DDMore                 = 0x04
	DDMaster               = 0x08
)

type PacketParserResult interface {
	GetType() uint8
}

type OSPFPacket struct {
	Timestamp time.Time //
	SourceIP  net.IP    //源ip
	DestIP    net.IP    //目的ip

	Version      uint8           //版本，ipv4或ipv6
	SubType      layers.OSPFType //协议子类型
	PacketLength uint16          //数据包长度
	RouterID     net.IP          //路由器ID
	AreaID       net.IP          //区域ID
	Checksum     uint16          //校验和
	AuType       uint16          //认证类型
	//鉴定字段，其数值根据验证类型而定： 当验证类型为0时未作定义。 类型为1时此字段为密码信息。 类型为2时此字段包括Key ID、验证数据长度和序列号的信息。
	Authentication uint64
	//////////////////////通过SubType类明确如下字段哪些是可用状态/////////////////////////
	HelloFields *HelloFields // Hello包特有字段

	DDFields *DDFields // DD包特有字段

	LSRFields *LSRFields // LSR特有字段

	LSUFields *LSUFields // LSU特有字段

	LSAckFields *LSAckFields // LSAck特有字段
}

// HelloFields 结构体定义了OSPF Hello报文的字段
type HelloFields struct {
	// NetworkMask 网络掩码,用于指定网络范围
	NetworkMask net.IPMask

	// HelloInterval Hello报文发送间隔(单位:秒)
	// 用于维持邻居关系,默认为10秒
	HelloInterval uint16

	// Options 可选项字段
	// 包含了各种OSPF功能选项的标志位
	Options uint32

	// Priority 路由器优先级
	// 用于DR/BDR选举,0表示不参与选举
	Priority uint8

	// DeadInterval 邻居失效时间间隔(单位:秒)
	// 通常是HelloInterval的4倍
	DeadInterval uint32

	// DesignatedRouter 指定路由器的IP地址
	DesignatedRouter net.IP

	// BackupDesignatedRouter 备份指定路由器的IP地址,在DR失效时接替其角色
	BackupDesignatedRouter net.IP

	// Neighbors 邻居路由器IP地址列表
	// 包含了当前已知的所有邻居路由器
	Neighbors []net.IP
}

type LSAHeader struct {
	LSAge       uint16
	LSType      uint16
	LinkStateID net.IP
	AdvRouter   net.IP
	LSSeqNumber uint32
	LSChecksum  uint16
	Length      uint16
	LSOptions   uint8
}

// IsRouterLSA LSA类型检查方法
func (h *LSAHeader) IsRouterLSA() bool {
	return h.LSType == 1
}

func (h *LSAHeader) IsNetworkLSA() bool {
	return h.LSType == 2
}

func (h *LSAHeader) IsSummaryLSA() bool {
	return h.LSType == 3 || h.LSType == 4
}

func (h *LSAHeader) IsASExternalLSA() bool {
	return h.LSType == 5
}

type DDFields struct {
	InterfaceMTU uint16
	Options      uint32
	Flags        uint16      // I、M、MS标志位
	DDSequence   uint32      // DD序列号
	LSAHeaders   []LSAHeader //
}

// IsMaster 检查是否是Master
func (d *DDFields) IsMaster() bool {
	return d.Flags&DDMaster != 0
}

// IsInitialize 检查是否设置了Initialize位
func (d *DDFields) IsInitialize() bool {
	return d.Flags&DDInitialize != 0
}

// HasMore 检查是否还有更多DD包
func (d *DDFields) HasMore() bool {
	return d.Flags&DDMore != 0
}

// HasNeighbor HelloFields 的辅助方法
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
	LSType    uint16 // 改为uint16
	LSID      net.IP
	AdvRouter net.IP
}

type LSUFields struct {
	NumOfLSAs uint32
	LSAs      []LSAFields
}

type LSAInfo struct {
	LSType uint16
}

type LSAFields struct {
	Header  LSAHeader
	Content LSAInfo
}

type LSAckFields struct {
	LSAHeaders []LSAHeader
}

// IsDDMaster OSPFPacket的辅助方法，用于更方便地访问DD包的标志位
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
