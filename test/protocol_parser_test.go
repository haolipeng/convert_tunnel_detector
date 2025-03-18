package main

import (
	"os"
	"testing"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket"
	"github.com/haolipeng/gopacket/layers"
	"github.com/haolipeng/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

// TestParseOSPFPacket 测试从PCAP文件中读取OSPF数据包并解析
func TestParseOSPFPacket(t *testing.T) {
	// 检查PCAP文件是否存在
	pcapFile := "../ospf.pcap"
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("PCAP文件不存在，跳过测试")
	}

	// 打开PCAP文件
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatalf("无法打开PCAP文件: %v", err)
	}
	defer handle.Close()

	// 创建协议解析器
	parser := processor.NewProtocolParser(1, nil)

	// 设置BPF过滤器只读取OSPF数据包
	err = handle.SetBPFFilter("ip proto ospf")
	if err != nil {
		t.Logf("设置BPF过滤器失败: %v", err)
	}

	// 读取数据包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	ospfHelloCount := 0
	ospfDDCount := 0
	ospfLSRCount := 0
	ospfLSUCount := 0
	ospfLSAckCount := 0

	for packet := range packetSource.Packets() {
		// 提取原始数据
		rawData := packet.Data()

		// 创建Packet结构
		packetData := &types.Packet{
			ID:        "",
			Timestamp: time.Now().UnixNano(),
			RawData:   rawData,
		}

		// 直接调用ParsePacket函数进行解析
		parsedPacket, err := parser.ParsePacket(packetData)
		assert.NoError(t, err, "解析数据包时出错")

		// 确保解析后的数据包不为空
		assert.NotNil(t, parsedPacket, "解析后的数据包不应为空")

		// 检查是否是OSPF协议
		if parsedPacket.Protocol == "ospf" {
			packetCount++

			// 检查ParserResult字段
			assert.NotNil(t, parsedPacket.ParserResult, "OSPF数据包的ParserResult不应为空")

			// 类型断言为OSPFPacket
			ospfPacket, ok := parsedPacket.ParserResult.(*processor.OSPFPacket)
			assert.True(t, ok, "ParserResult应该是OSPFPacket类型")
			assert.NotNil(t, ospfPacket, "OSPFPacket不应为空")

			// 基本字段验证
			assert.NotNil(t, ospfPacket.RouterID, "RouterID不应为空")
			assert.NotNil(t, ospfPacket.AreaID, "AreaID不应为空")
			assert.NotZero(t, ospfPacket.Version, "Version不应为0")

			// 根据不同的OSPF报文类型进行特定验证
			switch ospfPacket.SubType {
			case layers.OSPFHello:
				ospfHelloCount++
				assert.NotNil(t, ospfPacket.HelloFields, "Hello包的HelloFields不应为空")
				if ospfPacket.HelloFields != nil {
					// 验证Hello包特有字段
					assert.NotNil(t, ospfPacket.HelloFields.NetworkMask, "NetworkMask不应为空")
					assert.NotZero(t, ospfPacket.HelloFields.HelloInterval, "HelloInterval不应为0")
					assert.NotNil(t, ospfPacket.HelloFields.DesignatedRouter, "DesignatedRouter不应为空")
					assert.NotNil(t, ospfPacket.HelloFields.BackupDesignatedRouter, "BackupDesignatedRouter不应为空")

					// 高级字段验证（仅作示例，实际测试需根据具体PCAP内容调整）
					t.Logf("Hello包 - 路由器ID: %s, Hello间隔: %d秒, 死亡间隔: %d秒",
						ospfPacket.RouterID.String(),
						ospfPacket.HelloFields.HelloInterval,
						ospfPacket.HelloFields.DeadInterval)

					// 验证网络掩码格式
					maskStr := ospfPacket.HelloFields.NetworkMask.String()
					assert.NotEmpty(t, maskStr, "NetworkMask字符串不应为空")
					t.Logf("Hello包 - 网络掩码: %s", maskStr)

					// 验证邻居信息
					if len(ospfPacket.HelloFields.Neighbors) > 0 {
						t.Logf("Hello包 - 包含%d个邻居", len(ospfPacket.HelloFields.Neighbors))
						for i, neighbor := range ospfPacket.HelloFields.Neighbors {
							assert.NotNil(t, neighbor, "邻居%d的IP不应为空", i)
							t.Logf("  邻居%d: %s", i+1, neighbor.String())
						}
					}
				}

			case layers.OSPFDatabaseDescription:
				ospfDDCount++
				assert.NotNil(t, ospfPacket.DDFields, "DD包的DDFields不应为空")
				if ospfPacket.DDFields != nil {
					// 验证DD包特有字段
					assert.NotZero(t, ospfPacket.DDFields.InterfaceMTU, "InterfaceMTU不应为0")
					t.Logf("DD包 - MTU: %d, 序列号: %d, 标志位: 0x%04x",
						ospfPacket.DDFields.InterfaceMTU,
						ospfPacket.DDFields.DDSequence,
						ospfPacket.DDFields.Flags)

					// 验证标志位函数
					t.Logf("  Master标志: %v, Initialize标志: %v, More标志: %v",
						ospfPacket.DDFields.IsMaster(),
						ospfPacket.DDFields.IsInitialize(),
						ospfPacket.DDFields.HasMore())

					// 验证LSA头部列表
					if len(ospfPacket.DDFields.LSAHeaders) > 0 {
						t.Logf("  包含%d个LSA头部", len(ospfPacket.DDFields.LSAHeaders))
						for i, header := range ospfPacket.DDFields.LSAHeaders {
							assert.NotNil(t, header.LinkStateID, "LSA头部%d的LinkStateID不应为空", i)
							assert.NotNil(t, header.AdvRouter, "LSA头部%d的AdvRouter不应为空", i)
							t.Logf("  LSA头部%d - 类型: %d, 链路状态ID: %s, 通告路由器: %s",
								i+1, header.LSType, header.LinkStateID, header.AdvRouter)
						}
					}
				}

			case layers.OSPFLinkStateRequest:
				ospfLSRCount++
				assert.NotNil(t, ospfPacket.LSRFields, "LSR包的LSRFields不应为空")
				if ospfPacket.LSRFields != nil && len(ospfPacket.LSRFields.LSARequests) > 0 {
					t.Logf("LSR包 - 包含%d个LSA请求", len(ospfPacket.LSRFields.LSARequests))
					for i, req := range ospfPacket.LSRFields.LSARequests {
						assert.NotNil(t, req.LSID, "LSA请求%d的LSID不应为空", i)
						assert.NotNil(t, req.AdvRouter, "LSA请求%d的AdvRouter不应为空", i)
						t.Logf("  LSA请求%d - 类型: %d, 链路状态ID: %s, 通告路由器: %s",
							i+1, req.LSType, req.LSID, req.AdvRouter)
					}
				}

			case layers.OSPFLinkStateUpdate:
				ospfLSUCount++
				assert.NotNil(t, ospfPacket.LSUFields, "LSU包的LSUFields不应为空")
				if ospfPacket.LSUFields != nil {
					assert.Equal(t, int(ospfPacket.LSUFields.NumOfLSAs), len(ospfPacket.LSUFields.LSAs),
						"NumOfLSAs应与LSAs数量一致")
					t.Logf("LSU包 - 包含%d个LSA", ospfPacket.LSUFields.NumOfLSAs)

					for i, lsa := range ospfPacket.LSUFields.LSAs {
						t.Logf("  LSA%d - 类型: %d, 链路状态ID: %s, 通告路由器: %s",
							i+1, lsa.Header.LSType, lsa.Header.LinkStateID, lsa.Header.AdvRouter)

						// 根据LSA类型验证特定字段
						switch lsa.Header.LSType {
						case 1: // Router LSA
							t.Logf("    Router LSA - 标志位: 0x%02x, 链路数: %d",
								lsa.RouterLsa.Flags, lsa.RouterLsa.Links)
						case 5: // AS External LSA
							mask := processor.Uint32ToIP(lsa.ASExternalLsa.NetworkMask).String()
							t.Logf("    AS External LSA - 网络掩码: %s, 外部位: %v, 度量值: %d",
								mask, lsa.ASExternalLsa.ExternalBit, lsa.ASExternalLsa.Metric)
						}
					}
				}

			case layers.OSPFLinkStateAcknowledgment:
				ospfLSAckCount++
				assert.NotNil(t, ospfPacket.LSAckFields, "LSAck包的LSAckFields不应为空")
				if ospfPacket.LSAckFields != nil && len(ospfPacket.LSAckFields.LSAHeaders) > 0 {
					t.Logf("LSAck包 - 包含%d个LSA头部确认", len(ospfPacket.LSAckFields.LSAHeaders))
					for i, header := range ospfPacket.LSAckFields.LSAHeaders {
						assert.NotNil(t, header.LinkStateID, "LSA头部%d的LinkStateID不应为空", i)
						assert.NotNil(t, header.AdvRouter, "LSA头部%d的AdvRouter不应为空", i)
						t.Logf("  LSA头部%d - 类型: %d, 链路状态ID: %s, 通告路由器: %s",
							i+1, header.LSType, header.LinkStateID, header.AdvRouter)
					}
				}
			}
		}
	}

	// 验证读取到了数据包
	assert.Greater(t, packetCount, 0, "应至少解析到一个OSPF数据包")

	// 输出各类型数据包统计信息
	t.Logf("共解析OSPF数据包: %d个", packetCount)
	t.Logf("其中: Hello包: %d个, DD包: %d个, LSR包: %d个, LSU包: %d个, LSAck包: %d个",
		ospfHelloCount, ospfDDCount, ospfLSRCount, ospfLSUCount, ospfLSAckCount)
}
