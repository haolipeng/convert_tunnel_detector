package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface struct {
		Name        string        `yaml:"name"`
		SnapLen     int32         `yaml:"snaplen"`
		Promiscuous bool          `yaml:"promiscuous"`
		Timeout     time.Duration `yaml:"timeout"`
		BPFFilter   string        `yaml:"bpf_filter"`
	} `yaml:"interface"`

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
}

func (c *Config) Validate() error {
	if c.Interface.Name == "" {
		return fmt.Errorf("interface name is required")
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
