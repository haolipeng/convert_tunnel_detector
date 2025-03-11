package types

// OSPFPacket OSPF基础报文结构
type OSPFPacket struct {
	// OSPF通用头部字段
	Version   uint8  // 版本号
	Type      uint8  // 消息类型
	PacketLen uint16 // 报文长度
	SrcRouter string // 源路由器
	AreaID    string // 区域ID
	Checksum  uint16 // 校验和
	AuType    uint16 // 认证类型
	Auth      []byte // 认证数据

	// Hello包字段
	NetworkMask   string // 网络掩码
	HelloInterval uint16 // Hello间隔
	Priority      uint8  // 路由器优先级
	DeadInterval  uint32 // 失效间隔
	DR            string // 指定路由器
	BDR           string // 备用指定路由器

	// 其他类型包的数据
	Data interface{} // 根据Type字段确定具体类型
}

// OSPFDDPacket 数据库描述包
type OSPFDDPacket struct {
	InterfaceMTU uint16 // 接口MTU
	Options      uint8  // 选项
	Flags        uint8  // 标志
	SeqNum       uint32 // 序列号
	LSAs         []LSAHeader
}

// OSPFLSRPacket 链路状态请求包
type OSPFLSRPacket struct {
	LinkStateID string // 链路状态ID
	AdvRouter   string // 通告路由器
	LSType      uint32 // LSA类型
}

// OSPFLSUPacket 链路状态更新包
type OSPFLSUPacket struct {
	NumLSAs   uint32 // LSA数量
	LSAs      []LSA  // LSA列表
	AdvRouter string // 通告路由器
}

// OSPFLSAckPacket 链路状态确认包
type OSPFLSAckPacket struct {
	LSAHeaders        []LSAHeader // LSA头部列表
	LSASequenceNumber string      // LSA序列号
}

// LSAHeader LSA头部
type LSAHeader struct {
	LSAge         uint16 // LSA年龄
	Options       uint8  // 选项
	LSType        uint8  // LSA类型
	LinkStateID   string // 链路状态ID
	AdvRouter     string // 通告路由器
	LSSequenceNum int32  // LSA序列号
	LSChecksum    uint16 // LSA校验和
	Length        uint16 // 长度
}

// LSA 链路状态通告
type LSA struct {
	Header LSAHeader // LSA头部
	Data   []byte    // LSA数据
}

// GetType 实现PacketResult接口
func (p *OSPFPacket) GetType() PacketType {
	return OSPF
}
