package main

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"gopkg.in/yaml.v2"
	"log"
	"os"
)

// OSPFPacket OSPF报文结构定义
type OSPFPacket struct {
	// OSPF通用头部字段
	Version   uint8   `yaml:"version" cel:"ospf.version"`             // 版本号
	Type      uint8   `yaml:"msg" cel:"ospf.msg"`                     // 消息类型
	PacketLen uint16  `yaml:"packet_length" cel:"ospf.packet_length"` // 报文长度
	SrcRouter string  `yaml:"srcrouter" cel:"ospf.srcrouter"`         // 源路由器
	AreaID    string  `yaml:"area_id" cel:"ospf.area_id"`             // 区域ID
	Checksum  uint16  `yaml:"checksum" cel:"ospf.checksum"`           // 校验和
	AuType    uint16  `yaml:"auth.type" cel:"ospf.auth.type"`         // 认证类型
	Auth      [8]byte `yaml:"auth.none" cel:"ospf.auth.none"`         // 认证数据

	// Hello报文特有字段
	NetworkMask   string `yaml:"hello.network_mask" cel:"ospf.hello.network_mask"`                         // 网络掩码
	HelloInterval uint16 `yaml:"hello.hello_interval" cel:"ospf.hello.hello_interval"`                     // Hello间隔
	Options       uint32 `yaml:"v2.options" cel:"ospf.v2.options"`                                         // 可选项
	Priority      uint8  `yaml:"hello.router_priority" cel:"ospf.hello.router_priority"`                   // 路由器优先级
	DeadInterval  uint32 `yaml:"hello.router_dead_interval" cel:"ospf.hello.router_dead_interval"`         // 失效间隔
	DR            string `yaml:"hello.designated_router" cel:"ospf.hello.designated_router"`               // 指定路由器
	BDR           string `yaml:"hello.backup_designated_router" cel:"ospf.hello.backup_designated_router"` // 备用指定路由器
}

type RuleConfig struct {
	Description string `yaml:"description"`
	Expression  string `yaml:"expression"`
	Severity    string `yaml:"severity"`
}

type RulesConfig struct {
	Rules map[string]RuleConfig `yaml:"rules"`
}

type DetectionResult struct {
	Match   bool
	Details interface{}
}

type OSPFDetector struct {
	env      *cel.Env
	programs map[string]cel.Program
	rules    map[string]RuleConfig
}

func NewOSPFDetector(configPath string) (*OSPFDetector, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %v", err)
	}

	config := &RulesConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parse yaml: %v", err)
	}

	detector := &OSPFDetector{
		programs: make(map[string]cel.Program),
		rules:    config.Rules,
	}

	if err := detector.setupEnv(); err != nil {
		return nil, err
	}

	if err := detector.compileRules(); err != nil {
		return nil, err
	}

	return detector, nil
}
func (d *OSPFDetector) Detect(packet *OSPFPacket) map[string]*DetectionResult {
	results := make(map[string]*DetectionResult)

	// 构建完全扁平化的变量结构
	vars := map[string]interface{}{
		// 通用头部字段
		"ospf.version":       int64(packet.Version),
		"ospf.msg":           int64(packet.Type),
		"ospf.packet_length": int64(packet.PacketLen),
		"ospf.srcrouter":     packet.SrcRouter,
		"ospf.area_id":       packet.AreaID,
		"ospf.checksum":      int64(packet.Checksum),

		// Hello字段
		"ospf.hello.network_mask":             packet.NetworkMask,
		"ospf.hello.hello_interval":           int64(packet.HelloInterval),
		"ospf.hello.router_priority":          int64(packet.Priority),
		"ospf.hello.router_dead_interval":     int64(packet.DeadInterval),
		"ospf.hello.designated_router":        packet.DR,
		"ospf.hello.backup_designated_router": packet.BDR,

		// Auth字段
		"ospf.auth.type": int64(packet.AuType),
		"ospf.auth.none": string(packet.Auth[:]),

		// V2字段
		"ospf.v2.options": int64(packet.Options),
	}

	// 执行规则检查
	for name, prg := range d.programs {
		fmt.Printf("Evaluating rule: %s\n", name)
		out, _, err := prg.Eval(vars)
		if err != nil {
			fmt.Printf("Rule evaluation error: %v\n", err)
			results[name] = &DetectionResult{
				Match:   false,
				Details: err,
			}
			continue
		}

		match, ok := out.Value().(bool)
		results[name] = &DetectionResult{
			Match: ok && match,
		}
		fmt.Printf("Rule %s result: match=%v, ok=%v\n", name, match, ok)
	}

	return results
}

func (d *OSPFDetector) setupEnv() error {
	// 创建CEL环境
	env, err := cel.NewEnv(
		cel.Declarations(
			// 通用头部字段
			decls.NewVar("ospf.version", decls.Int),
			decls.NewVar("ospf.msg", decls.Int),
			decls.NewVar("ospf.packet_length", decls.Int),
			decls.NewVar("ospf.srcrouter", decls.String),
			decls.NewVar("ospf.area_id", decls.String),
			decls.NewVar("ospf.checksum", decls.Int),

			// Hello字段
			decls.NewVar("ospf.hello.network_mask", decls.String),
			decls.NewVar("ospf.hello.hello_interval", decls.Int),
			decls.NewVar("ospf.hello.router_priority", decls.Int),
			decls.NewVar("ospf.hello.router_dead_interval", decls.Int),
			decls.NewVar("ospf.hello.designated_router", decls.String),
			decls.NewVar("ospf.hello.backup_designated_router", decls.String),

			// Auth字段
			decls.NewVar("ospf.auth.type", decls.Int),
			decls.NewVar("ospf.auth.none", decls.String),

			// V2字段
			decls.NewVar("ospf.v2.options", decls.Int),
		),
	)
	if err != nil {
		return fmt.Errorf("create cel env: %v", err)
	}

	d.env = env
	return nil
}

func (d *OSPFDetector) compileRules() error {
	for name, rule := range d.rules {
		fmt.Printf("Compiling rule: %s -> %s\n", name, rule.Expression)

		ast, iss := d.env.Compile(rule.Expression)
		if iss != nil && iss.Err() != nil {
			return fmt.Errorf("compile %s: %v", name, iss.Err())
		}

		checked, iss := d.env.Check(ast)
		if iss != nil && iss.Err() != nil {
			return fmt.Errorf("check %s: %v", name, iss.Err())
		}

		prg, err := d.env.Program(checked)
		if err != nil {
			return fmt.Errorf("program %s: %v", name, err)
		}

		d.programs[name] = prg
	}
	return nil
}

func main() {
	// 创建检测器
	detector, err := NewOSPFDetector("./rules.yaml")
	if err != nil {
		log.Fatal(err)
	}

	// 创建测试数据包
	packet := &OSPFPacket{
		Version:       2, // 添加版本号
		SrcRouter:     "192.168.170.3",
		Type:          3,
		HelloInterval: 10,
		NetworkMask:   "255.255.255.0",
	}

	// 执行检测
	results := detector.Detect(packet)

	// 处理结果并打印所有规则的结果
	for name, result := range results {
		rule := detector.rules[name]
		fmt.Printf("Rule: %s\n", name)
		fmt.Printf("  Description: %s\n", rule.Description)
		fmt.Printf("  Expression: %s\n", rule.Expression)
		fmt.Printf("  Match: %v\n", result.Match)
		fmt.Printf("  Details: %v\n", result.Details)
	}
}
