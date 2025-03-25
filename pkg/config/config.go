package config

import (
	"fmt"
	"os"
	"time"

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

type Config struct {
	Pipeline struct {
		WorkerCount int `yaml:"worker_count"`
		BufferSize  int `yaml:"buffer_size"`
	} `yaml:"pipeline"`
	Log struct {
		Level      string `yaml:"level"`
		Dir        string `yaml:"dir"`
		Filename   string `yaml:"filename"`
		MaxAge     int    `yaml:"max_age"`
		RotateTime int    `yaml:"rotate_time"`
		TimeFormat string `yaml:"time_format"`
	} `yaml:"log"`
	Output struct {
		Type     string `yaml:"type"`
		Filename string `yaml:"filename"`
	} `yaml:"output"`
	Source      SourceConfig      `yaml:"source"`
	API         APIConfig         `yaml:"api"`
	RuleEngine  RuleEngineConfig  `yaml:"rule_engine"`
	Timeouts    TimeoutsConfig    `yaml:"timeouts"`
	Permissions PermissionsConfig `yaml:"permissions"`
}

func (c *Config) Validate() error {
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

	// 设置默认值
	if c.API.Port == "" {
		c.API.Port = "8080"
	}

	if c.RuleEngine.RuleDirectory == "" {
		c.RuleEngine.RuleDirectory = "rules/"
	}

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
