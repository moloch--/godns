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
	"testing"
)

func TestYaml1(t *testing.T) {
	// Parse a config file from a given path
	conf, err := ParseConfigFile("test/test1.yaml")
	if err != nil {
		t.Error(err)
	}

	// Test Server Values
	if conf.Server == nil {
		t.Errorf("Server config is required")
	}
	if conf.Server.Net != "tcp" {
		t.Errorf("config server.net should be 'tcp' got %s", conf.Server.Net)
	}
	if conf.Server.Host != "127.0.0.1" {
		t.Errorf("config server.host should be '127.0.0.1' got %s", conf.Server.Host)
	}
	if conf.Server.ListenPort != uint16(31337) {
		t.Errorf("config server.listen_port should be '31337' got %d", conf.Server.ListenPort)
	}

	// Test Client Values
	if conf.Client == nil {
		t.Errorf("Client config is required")
	}
	if conf.Client.DialTimeout != "1m" {
		t.Errorf("config client.dial_timeout should be '1m' got %s", conf.Client.DialTimeout)
	}
	if conf.Client.ReadTimeout != "1m" {
		t.Errorf("config client.read_timeout should be '1m' got %s", conf.Client.ReadTimeout)
	}
	if conf.Client.WriteTimeout != "1m" {
		t.Errorf("config client.write_timeout should be '1m' got %s", conf.Client.WriteTimeout)
	}

	// Test Upstreams
	if len(conf.Upstreams) != 2 {
		t.Errorf("config upstreams should have 2 entries got %v", conf.Upstreams)
	}

	// Test A Rules
	if aRules, ok := conf.Rules["A"]; ok {
		if len(aRules) != 2 {
			t.Errorf("config rules should have 1 A entry got %v", aRules)
		}

		if aRules[0].Priority != 1 {
			t.Errorf("config rules should have an A entry with priority 1 got %d", aRules[0].Priority)
		}
		if aRules[0].IsRegExp != true {
			t.Errorf("config rules should have an A entry with is_regexp true got %v", aRules[0].IsRegExp)
		}
		if aRules[0].Match != ".*" {
			t.Errorf("config rules should have an A entry with match .* got %s", aRules[0].Match)
		}
		if aRules[0].Spoof != "127.0.0.1" {
			t.Errorf("config rules should have an A entry with spoof, got %s", aRules[0].Spoof)
		}
		if len(aRules[0].SourceIPs) != 1 {
			t.Errorf("config rules should have an A entry with source_ips, got %v", aRules[0].SourceIPs)
		}
	} else {
		t.Errorf("config rules should have an A entry")
	}

	// Test MX Rules
	if mxRules, ok := conf.Rules["MX"]; ok {
		if len(mxRules) != 1 {
			t.Errorf("config rules should have 1 MX entry got %v", mxRules)
		}

		if mxRules[0].Priority != 1 {
			t.Errorf("config rules should have an MX entry with priority 1 got %d", mxRules[0].Priority)
		}
		if mxRules[0].IsRegExp != true {
			t.Errorf("config rules should have an MX entry with is_regexp true got %v", mxRules[0].IsRegExp)
		}
		if mxRules[0].Match != ".*" {
			t.Errorf("config rules should have an MX entry with match .* got %s", mxRules[0].Match)
		}
		if mxRules[0].Spoof != "127.0.0.1" {
			t.Errorf("config rules should have an MX entry with spoof, got %s", mxRules[0].Spoof)
		}
	} else {
		t.Errorf("config rules should have an MX entry")
	}

	if soaRules, ok := conf.Rules["SOA"]; ok {
		if len(soaRules) != 1 {
			t.Errorf("config rules should have 1 SOA entry got %v", soaRules)
		}

		if soaRules[0].Priority != 1 {
			t.Errorf("config rules should have an SOA entry with priority 1 got %d", soaRules[0].Priority)
		}
		if soaRules[0].SpoofMName != "ns1.example.com" {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRName != "hostmaster.example.com" {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofSerial != 1 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRefresh != 2 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRetry != 3 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofExpire != 4 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofMinTTL != 5 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
	} else {
		t.Errorf("config rules should have an SOA entry")
	}

	if srvRules, ok := conf.Rules["SRV"]; ok {
		if len(srvRules) != 1 {
			t.Errorf("config rules should have 1 SRV entry got %v", srvRules)
		}

		if srvRules[0].Priority != 1 {
			t.Errorf("config rules should have an SRV entry with priority 1 got %d", srvRules[0].Priority)
		}
		if srvRules[0].SpoofPriority != 1 {
			t.Errorf("config rules should have an SRV entry with spoof_priority 1 got %d", srvRules[0].SpoofPriority)
		}
		if srvRules[0].SpoofWeight != 2 {
			t.Errorf("config rules should have an SRV entry with spoof_weight 1 got %d", srvRules[0].SpoofWeight)
		}
		if srvRules[0].SpoofPort != 3 {
			t.Errorf("config rules should have an SRV entry with spoof_port 1 got %d", srvRules[0].SpoofPort)
		}
	} else {
		t.Errorf("config rules should have an SRV entry")
	}
}

func TestJson1(t *testing.T) {
	// Parse a config file from a given path
	conf, err := ParseConfigFile("test/test1.json")
	if err != nil {
		t.Error(err)
	}

	// Test Server Values
	if conf.Server == nil {
		t.Errorf("Server config is required")
	}
	if conf.Server.Net != "tcp" {
		t.Errorf("config server.net should be 'tcp' got %s", conf.Server.Net)
	}
	if conf.Server.Host != "127.0.0.1" {
		t.Errorf("config server.host should be '127.0.0.1' got %s", conf.Server.Host)
	}
	if conf.Server.ListenPort != uint16(31337) {
		t.Errorf("config server.listen_port should be '31337' got %d", conf.Server.ListenPort)
	}

	// Test Client Values
	if conf.Client == nil {
		t.Errorf("Client config is required")
	}
	if conf.Client.DialTimeout != "1m" {
		t.Errorf("config client.dial_timeout should be '1m' got %s", conf.Client.DialTimeout)
	}
	if conf.Client.ReadTimeout != "1m" {
		t.Errorf("config client.read_timeout should be '1m' got %s", conf.Client.ReadTimeout)
	}
	if conf.Client.WriteTimeout != "1m" {
		t.Errorf("config client.write_timeout should be '1m' got %s", conf.Client.WriteTimeout)
	}

	// Test Upstreams
	if len(conf.Upstreams) != 2 {
		t.Errorf("config upstreams should have 2 entries got %v", conf.Upstreams)
	}

	// Test A Rules
	if aRules, ok := conf.Rules["A"]; ok {
		if len(aRules) != 2 {
			t.Errorf("config rules should have 1 A entry got %v", aRules)
		}

		if aRules[0].Priority != 1 {
			t.Errorf("config rules should have an A entry with priority 1 got %d", aRules[0].Priority)
		}
		if aRules[0].IsRegExp != true {
			t.Errorf("config rules should have an A entry with is_regexp true got %v", aRules[0].IsRegExp)
		}
		if aRules[0].Match != ".*" {
			t.Errorf("config rules should have an A entry with match .* got %s", aRules[0].Match)
		}
		if aRules[0].Spoof != "127.0.0.1" {
			t.Errorf("config rules should have an A entry with spoof, got %s", aRules[0].Spoof)
		}
		if len(aRules[0].SourceIPs) != 1 {
			t.Errorf("config rules should have an A entry with source_ips, got %v", aRules[0].SourceIPs)
		}
	} else {
		t.Errorf("config rules should have an A entry")
	}

	// Test MX Rules
	if mxRules, ok := conf.Rules["MX"]; ok {
		if len(mxRules) != 1 {
			t.Errorf("config rules should have 1 MX entry got %v", mxRules)
		}

		if mxRules[0].Priority != 1 {
			t.Errorf("config rules should have an MX entry with priority 1 got %d", mxRules[0].Priority)
		}
		if mxRules[0].IsRegExp != true {
			t.Errorf("config rules should have an MX entry with is_regexp true got %v", mxRules[0].IsRegExp)
		}
		if mxRules[0].Match != ".*" {
			t.Errorf("config rules should have an MX entry with match .* got %s", mxRules[0].Match)
		}
		if mxRules[0].Spoof != "127.0.0.1" {
			t.Errorf("config rules should have an MX entry with spoof, got %s", mxRules[0].Spoof)
		}
	} else {
		t.Errorf("config rules should have an MX entry")
	}

	if soaRules, ok := conf.Rules["SOA"]; ok {
		if len(soaRules) != 1 {
			t.Errorf("config rules should have 1 SOA entry got %v", soaRules)
		}

		if soaRules[0].Priority != 1 {
			t.Errorf("config rules should have an SOA entry with priority 1 got %d", soaRules[0].Priority)
		}
		if soaRules[0].SpoofMName != "ns1.example.com" {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRName != "hostmaster.example.com" {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofSerial != 1 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRefresh != 2 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofRetry != 3 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofExpire != 4 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
		if soaRules[0].SpoofMinTTL != 5 {
			t.Errorf("config rules should have an SOA entry with spoof, got %s", soaRules[0].Spoof)
		}
	} else {
		t.Errorf("config rules should have an SOA entry")
	}

	if srvRules, ok := conf.Rules["SRV"]; ok {
		if len(srvRules) != 1 {
			t.Errorf("config rules should have 1 SRV entry got %v", srvRules)
		}

		if srvRules[0].Priority != 1 {
			t.Errorf("config rules should have an SRV entry with priority 1 got %d", srvRules[0].Priority)
		}
		if srvRules[0].SpoofPriority != 1 {
			t.Errorf("config rules should have an SRV entry with spoof_priority 1 got %d", srvRules[0].SpoofPriority)
		}
		if srvRules[0].SpoofWeight != 2 {
			t.Errorf("config rules should have an SRV entry with spoof_weight 1 got %d", srvRules[0].SpoofWeight)
		}
		if srvRules[0].SpoofPort != 3 {
			t.Errorf("config rules should have an SRV entry with spoof_port 1 got %d", srvRules[0].SpoofPort)
		}
	} else {
		t.Errorf("config rules should have an SRV entry")
	}
}
