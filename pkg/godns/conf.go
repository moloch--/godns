package godns

import (
	"encoding/json"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// ParseConfigFile - Parse a config file from a given path
func ParseConfigFile(filePath string) (*GodNSConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(filePath, ".json") {
		return ParseJSONConfig(data)
	}
	if strings.HasSuffix(filePath, ".yml") || strings.HasSuffix(filePath, ".yaml") {
		return ParseYAMLConfig(data)
	}

	// Default to yaml
	return ParseYAMLConfig(data)
}

// ParseJSONConfig - Parse a JSON config file
func ParseJSONConfig(data []byte) (*GodNSConfig, error) {
	conf := &GodNSConfig{}
	err := json.Unmarshal(data, conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// ParseYAMLConfig - Parse a YAML config file
func ParseYAMLConfig(data []byte) (*GodNSConfig, error) {
	conf := &GodNSConfig{}
	err := yaml.Unmarshal(data, conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}
