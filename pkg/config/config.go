package config

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type InterfaceConfig struct {
	Name        string        `yaml:"name"`
	Snaplen     int32         `yaml:"snaplen"`
	Promiscuous bool          `yaml:"promiscuous"`
	Timeout     time.Duration `yaml:"timeout"`
	BPFFilter   string        `yaml:"bpf_filter"`
}

type SourceConfig struct {
	Type      string          `yaml:"type"`
	Filename  string          `yaml:"filename,omitempty"`
	Interface InterfaceConfig `yaml:"interface,omitempty"`
}

type APIConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type RuleEngineConfig struct {
	RuleDirectory string `yaml:"rule_directory"`
}

type TimeoutsConfig struct {
	ProcessorReadySeconds int `yaml:"processor_ready_seconds"`
	SinkReadySeconds      int `yaml:"sink_ready_seconds"`
	ShutdownSeconds       int `yaml:"shutdown_seconds"`
	ProcessorStopSeconds  int `yaml:"processor_stop_seconds"`
}

type PermissionsConfig struct {
	DirectoryMode int `yaml:"directory_mode"`
	FileMode      int `yaml:"file_mode"`
}

type Output struct {
	Type              string `yaml:"type"`
	BaseFilename      string `yaml:"base_filename"`
	MaxFileSize       int64  `yaml:"max_file_size"`
	AlertEndpoint     string `yaml:"alert_endpoint"`
	BaseDirectory     string `yaml:"base_directory"`
	AllowAbsolutePath bool   `yaml:"allow_absolute_path"`
}

type Log struct {
	Level      string `yaml:"level"`
	Dir        string `yaml:"dir"`
	Filename   string `yaml:"filename"`
	MaxAge     int    `yaml:"max_age"`
	RotateTime int    `yaml:"rotate_time"`
	TimeFormat string `yaml:"time_format"`
}

type Pipeline struct {
	WorkerCount int `yaml:"worker_count"`
	BufferSize  int `yaml:"buffer_size"`
}

type SecurityConfig struct {
	HTTPTimeout         time.Duration `yaml:"http_timeout"`
	MaxIdleConns        int           `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int           `yaml:"max_idle_conns_per_host"`
	IdleConnTimeout     time.Duration `yaml:"idle_conn_timeout"`
}

type Config struct {
	Pipeline    Pipeline          `yaml:"pipeline"`
	Log         Log               `yaml:"log"`
	Output      Output            `yaml:"output"`
	Source      SourceConfig      `yaml:"source"`
	API         APIConfig         `yaml:"api"`
	RuleEngine  RuleEngineConfig  `yaml:"rule_engine"`
	Timeouts    TimeoutsConfig    `yaml:"timeouts"`
	Permissions PermissionsConfig `yaml:"permissions"`
	Security    SecurityConfig    `yaml:"security"`
}

const (
	// 文件大小限制（字节）
	MinFileSize     = 1024 * 1024       // 1MB
	MaxFileSize     = 200 * 1024 * 1024 // 200MB
	DefaultFileSize = 50 * 1024 * 1024  // 50MB
)

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	// 验证输出配置
	if c.Output.Type == "" {
		return fmt.Errorf("output type is required")
	}

	if c.Output.BaseFilename == "" {
		return fmt.Errorf("output base_filename is required")
	}

	if c.Output.MaxFileSize > 0 {
		if c.Output.MaxFileSize < MinFileSize {
			return fmt.Errorf("max_file_size must be at least %d bytes (1MB)", MinFileSize)
		}
		if c.Output.MaxFileSize > MaxFileSize {
			return fmt.Errorf("max_file_size cannot exceed %d bytes (1GB)", MaxFileSize)
		}
	} else {
		// 如果没有设置，使用默认值
		c.Output.MaxFileSize = DefaultFileSize
		logrus.Warnf("max_file_size not set, using default value: %d bytes", DefaultFileSize)
	}

	// 验证源配置
	if c.Source.Type == "live" && c.Source.Interface.Name == "" {
		return fmt.Errorf("interface name is required for live capture")
	}
	if c.Source.Type == "file" && c.Source.Filename == "" {
		return fmt.Errorf("filename is required for file source")
	}
	if c.Pipeline.WorkerCount <= 0 {
		return fmt.Errorf("worker count must be positive")
	}
	if c.Pipeline.BufferSize <= 0 {
		return fmt.Errorf("buffer size must be positive")
	}

	// 验证API配置
	if c.API.Port == "" {
		return fmt.Errorf("api port is required")
	}

	// 验证规则引擎配置
	if c.RuleEngine.RuleDirectory == "" {
		return fmt.Errorf("rule_engine rule_dir is required")
	}

	// 验证超时配置
	if c.Timeouts.ProcessorReadySeconds <= 0 {
		c.Timeouts.ProcessorReadySeconds = 10
	}

	if c.Timeouts.SinkReadySeconds <= 0 {
		c.Timeouts.SinkReadySeconds = 5
	}

	if c.Timeouts.ShutdownSeconds <= 0 {
		c.Timeouts.ShutdownSeconds = 5
	}

	if c.Timeouts.ProcessorStopSeconds <= 0 {
		c.Timeouts.ProcessorStopSeconds = 30
	}

	if c.Permissions.DirectoryMode <= 0 {
		c.Permissions.DirectoryMode = 0755
	}

	if c.Permissions.FileMode <= 0 {
		c.Permissions.FileMode = 0644
	}

	if c.Log.TimeFormat == "" {
		c.Log.TimeFormat = "2006-01-02 15:04:05"
	}

	// 验证安全配置
	if c.Security.HTTPTimeout <= 0 {
		c.Security.HTTPTimeout = 5 * time.Second
	}
	if c.Security.MaxIdleConns <= 0 {
		c.Security.MaxIdleConns = 100
	}
	if c.Security.MaxIdleConnsPerHost <= 0 {
		c.Security.MaxIdleConnsPerHost = 100
	}
	if c.Security.IdleConnTimeout <= 0 {
		c.Security.IdleConnTimeout = 90 * time.Second
	}

	// 验证输出配置
	if c.Output.BaseDirectory == "" {
		c.Output.BaseDirectory = "." // 默认使用当前目录
	}

	return nil
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}
