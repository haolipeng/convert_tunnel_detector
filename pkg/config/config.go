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
	} `yaml:"log"`
	Output struct {
		Type     string `yaml:"type"`
		Filename string `yaml:"filename"`
	} `yaml:"output"`
	Source SourceConfig `yaml:"source"`
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
