package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Mappings []Mapping `json:"mappings"`
}

type Mapping struct {
	Patterns              []string `json:"patterns"`
	Address               string   `json:"address"`
	SNI                   string   `json:"sni"`
	EchHost               string   `json:"ech_host"`
	EchConfigList         string   `json:"ech_configlist"`
	EchConfigListDisabled bool     `json:"-"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
