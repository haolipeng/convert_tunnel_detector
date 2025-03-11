package processor

import (
	"fmt"
	"net"

	"github.com/haolipeng/gopacket/layers"
	"github.com/sirupsen/logrus"
)

type OSPFParser struct {
}

// NewOSPFParser 创建一个ospf类型解析器
func NewOSPFParser() *OSPFParser {
	return &OSPFParser{}
}

// parsePacketV3 解析OSPFv3包
func (p *OSPFParser) parsePacketV3(ip *layers.IPv4, ospf *layers.OSPFv3) (*OSPFPacket, error) {
	//TODO:need implement me
	var err error
	return nil, err
}

// parsePacketV2 解析OSPFv2包
func (p *OSPFParser) parsePacketV2(ip *layers.IPv4, ospf *layers.OSPFv2) (*OSPFPacket, error) {
	// 创建基础OSPFPacket
	ospfPkt := &OSPFPacket{
		SourceIP:       ip.SrcIP,
		DestIP:         ip.DstIP,
		Version:        ospf.Version,
		SubType:        ospf.Type,
		PacketLength:   ospf.PacketLength,
		RouterID:       Uint32ToIP(ospf.RouterID),
		AreaID:         Uint32ToIP(ospf.AreaID),
		Checksum:       ospf.Checksum,
		AuType:         ospf.AuType,
		Authentication: ospf.Authentication,
	}

	// 根据包类型解析具体内容
	switch ospf.Type {
	case layers.OSPFHello: //解析Hello包
		if err := p.parseHelloPacket(ospf.Content, ospfPkt); err != nil {
			return nil, err
		}
	case layers.OSPFDatabaseDescription: //解析DD包
		if err := p.parseDDPacket(ospf.Content, ospfPkt); err != nil {
			return nil, err
		}
	case layers.OSPFLinkStateRequest: //解析LSR包
		if err := p.parseLSRPacket(ospf.Content, ospfPkt); err != nil {
			return nil, err
		}
	case layers.OSPFLinkStateUpdate: //解析LSU包
		if err := p.parseLSUPacket(ospf.Content, ospfPkt); err != nil {
			return nil, err
		}
	case layers.OSPFLinkStateAcknowledgment: //解析LSAck包
		if err := p.parseLSAckPacket(ospf.Content, ospfPkt); err != nil {
			return nil, err
		}
	default: //不支持的包类型,记录日志
		logrus.Errorf("this OSPF packet is not supported! please fix it!\n")
	}

	return ospfPkt, nil
}

// parseHelloPacket 解析Hello包内容
func (p *OSPFParser) parseHelloPacket(content interface{}, ospfPkt *OSPFPacket) error {
	// 首先尝试HelloPkgV2类型
	if hello, ok := content.(layers.HelloPkgV2); ok {
		ospfPkt.HelloFields = &HelloFields{
			NetworkMask:            net.IPMask(Uint32ToIP(hello.NetworkMask)),
			HelloInterval:          hello.HelloInterval,
			Options:                hello.Options,
			Priority:               hello.RtrPriority,
			DeadInterval:           hello.RouterDeadInterval,
			DesignatedRouter:       Uint32ToIP(hello.DesignatedRouterID),
			BackupDesignatedRouter: Uint32ToIP(hello.BackupDesignatedRouterID),
			Neighbors:              make([]net.IP, len(hello.NeighborID)),
		}

		// 转换邻居IP
		for i, neighbor := range hello.NeighborID {
			ospfPkt.HelloFields.Neighbors[i] = Uint32ToIP(neighbor)
		}
		return nil
	}

	// 然后尝试HelloPkg类型
	if hello, ok := content.(layers.HelloPkg); ok {
		ospfPkt.HelloFields = &HelloFields{
			NetworkMask:            net.IPMask(Uint32ToIP(0)), //HelloPkg没有NetworkMask
			HelloInterval:          hello.HelloInterval,
			Options:                hello.Options,
			Priority:               hello.RtrPriority,
			DeadInterval:           hello.RouterDeadInterval,
			DesignatedRouter:       Uint32ToIP(hello.DesignatedRouterID),
			BackupDesignatedRouter: Uint32ToIP(hello.BackupDesignatedRouterID),
			Neighbors:              make([]net.IP, len(hello.NeighborID)),
		}

		// 转换邻居IP
		for i, neighbor := range hello.NeighborID {
			ospfPkt.HelloFields.Neighbors[i] = Uint32ToIP(neighbor)
		}
		return nil
	}

	return fmt.Errorf("invalid Hello packet content: neither HelloPkgV2 nor HelloPkg")
}

// parseDDPacket 解析DD包内容
func (p *OSPFParser) parseDDPacket(content interface{}, ospfPkt *OSPFPacket) error {
	dd, ok := content.(layers.DbDescPkg)
	if !ok {
		return fmt.Errorf("invalid DD packet content")
	}

	ospfPkt.DDFields = &DDFields{
		InterfaceMTU: dd.InterfaceMTU,
		Options:      dd.Options,
		Flags:        dd.Flags,
		DDSequence:   dd.DDSeqNumber,
		LSAHeaders:   make([]LSAHeader, len(dd.LSAinfo)),
	}

	// 转换LSA Headers
	for i, lsa := range dd.LSAinfo {
		ospfPkt.DDFields.LSAHeaders[i] = LSAHeader{
			LSAge:       lsa.LSAge,
			LSOptions:   lsa.LSOptions,
			LSType:      lsa.LSType,
			LinkStateID: Uint32ToIP(lsa.LinkStateID),
			AdvRouter:   Uint32ToIP(lsa.AdvRouter),
			LSSeqNumber: lsa.LSSeqNumber,
			LSChecksum:  lsa.LSChecksum,
			Length:      lsa.Length,
		}
	}

	return nil
}

// 添加LSR包解析函数
func (p *OSPFParser) parseLSRPacket(content interface{}, ospfPkt *OSPFPacket) error {
	// 尝试类型断言
	lsrs, ok := content.([]layers.LSReq)
	if !ok {
		return fmt.Errorf("invalid LSR packet content: convert failed")
	}

	if len(lsrs) <= 0 {
		return fmt.Errorf("LSReq slice is empty")
	}

	//创建LSRFields对象
	ospfPkt.LSRFields = &LSRFields{
		LSARequests: make([]LSARequest, len(lsrs)),
	}

	//遍历LSR数组
	for i, lsr := range lsrs {
		v := LSARequest{
			LSType:    lsr.LSType,
			LSID:      Uint32ToIP(lsr.LSID),
			AdvRouter: Uint32ToIP(lsr.AdvRouter),
		}
		ospfPkt.LSRFields.LSARequests[i] = v
	}

	return nil
}

// parseLSUPacket 解析LSU包内容
func (p *OSPFParser) parseLSUPacket(content interface{}, ospfPkt *OSPFPacket) error {
	lsu, ok := content.(layers.LSUpdate)
	if !ok {
		return fmt.Errorf("invalid LSU packet content: unknown type %T", content)
	}

	ospfPkt.LSUFields = &LSUFields{
		NumOfLSAs: lsu.NumOfLSAs,
		LSAs:      make([]LSAFields, 0, lsu.NumOfLSAs),
	}

	// 解析LSAs
	for _, lsa := range lsu.LSAs {
		newLSA := LSAFields{
			Header: LSAHeader{
				LSAge:       lsa.LSAheader.LSAge,
				LSOptions:   lsa.LSAheader.LSOptions,
				LSType:      lsa.LSAheader.LSType,
				LinkStateID: Uint32ToIP(lsa.LSAheader.LinkStateID),
				AdvRouter:   Uint32ToIP(lsa.LSAheader.AdvRouter),
				LSSeqNumber: lsa.LSAheader.LSSeqNumber,
				LSChecksum:  lsa.LSAheader.LSChecksum,
				Length:      lsa.LSAheader.Length,
			},
		}

		err := p.extractLSAInformation(content, lsa, &newLSA)
		if err != nil {
			return err
		}

		ospfPkt.LSUFields.LSAs = append(ospfPkt.LSUFields.LSAs, newLSA)
	}

	return nil
}

// extractLSAInformation 提取LSA信息
func (p *OSPFParser) extractLSAInformation(content interface{}, lsa layers.LSA, newLSA *LSAFields) error {
	switch lsa.LSAheader.LSType {
	case RouterLSAtypeV2: //1
		//router lsa
		routerLSAInfo, ok := content.(layers.RouterLSAV2)
		if !ok {
			return fmt.Errorf("invalid LSU packet content: unknown RouterLSAtypeV2 type")
		}
		newLSA.RouterLsa.Flags = routerLSAInfo.Flags
		newLSA.RouterLsa.Links = routerLSAInfo.Links
		for _, r := range routerLSAInfo.Routers {
			router := RouterV2{
				Type:     r.Type,
				LinkID:   r.LinkID,
				LinkData: r.LinkData,
				Metric:   r.Metric,
			}
			newLSA.RouterLsa.Routers = append(newLSA.RouterLsa.Routers, router)
		}
	case NSSALSAtypeV2: //7
		//NSSA-LSA，由NSSA的ASBR产生，仅在本NSSA内传播。格式与Type5相同
		//所以使用fallthrough
		fallthrough
	case ASExternalLSAtypeV2: //5
		asExLsaInfo, ok := content.(layers.ASExternalLSAV2)
		if !ok {
			return fmt.Errorf("invalid LSU packet content: unknown ASExternalLSAtypeV2 type")
		}
		newLSA.ASExternalLsa.NetworkMask = asExLsaInfo.NetworkMask
		newLSA.ASExternalLsa.ExternalBit = asExLsaInfo.ExternalBit
		newLSA.ASExternalLsa.Metric = asExLsaInfo.Metric
		newLSA.ASExternalLsa.ForwardingAddress = asExLsaInfo.ForwardingAddress
		newLSA.ASExternalLsa.ExternalRouteTag = asExLsaInfo.ExternalRouteTag

	case NetworkLSAtypeV2: //2
		//network lsa
		networkLsaInfo, ok := content.(layers.NetworkLSAV2)
		if !ok {
			return fmt.Errorf("invalid LSU packet content: unknown NetworkLSAtypeV2 type")
		}
		newLSA.NetworkLsa.NetworkMask = networkLsaInfo.NetworkMask
		newLSA.NetworkLsa.AttachedRouter = append(newLSA.NetworkLsa.AttachedRouter, networkLsaInfo.AttachedRouter...)
	case SummaryLSANetworktypeV2: //3
		//Network-summary-LSA，描述区域内所有网段的路由，并通告给其他相关区域。
		//Type3和Type4的LSA有相同的格式
		fallthrough
	case SummaryLSAASBRtypeV2: //4
		logrus.Errorf("SummaryLSANetworktypeV2 and SummaryLSAASBRtypeV2 is not supported\n")
		return fmt.Errorf("SummaryLSANetworktypeV2 and SummaryLSAASBRtypeV2 is not supported")
	default:
		logrus.Errorf("Unknown LSA type, please fix it\n")
		return fmt.Errorf("unknown LSA type, please fix it")
	}
	return nil
}

// 添加LSAck包解析函数
func (p *OSPFParser) parseLSAckPacket(content interface{}, ospfPkt *OSPFPacket) error {
	// 类型断言为[]LSAheader,是切片类型
	lsaHeaders, ok := content.([]layers.LSAheader)
	if !ok {
		return fmt.Errorf("invalid LSAck packet content: unknown type %T", content)
	}

	ospfPkt.LSAckFields = &LSAckFields{
		LSAHeaders: make([]LSAHeader, len(lsaHeaders)),
	}

	// 解析每个LSA header
	for i, header := range lsaHeaders {
		ospfPkt.LSAckFields.LSAHeaders[i] = LSAHeader{
			LSAge:       header.LSAge,
			LSOptions:   header.LSOptions,
			LSType:      header.LSType,
			LinkStateID: Uint32ToIP(header.LinkStateID),
			AdvRouter:   Uint32ToIP(header.AdvRouter),
			LSSeqNumber: header.LSSeqNumber,
			LSChecksum:  header.LSChecksum,
			Length:      header.Length,
		}
	}

	return nil
}
