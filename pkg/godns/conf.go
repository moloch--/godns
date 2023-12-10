package godns

/*
	God Name Server (godns)
	Copyright (C) 2023  moloch--

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
