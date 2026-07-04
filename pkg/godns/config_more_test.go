package godns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func validGodNSConfig() *GodNSConfig {
	return &GodNSConfig{
		Server: &ServerConfig{
			Host:       "127.0.0.1",
			ListenPort: 1053,
		},
		Client: &ClientConfig{
			DialTimeout:  "250ms",
			ReadTimeout:  "500ms",
			WriteTimeout: "750ms",
		},
		Upstreams: []string{"192.0.2.53"},
		Rules: map[string][]*ReplacementRule{
			"A": {
				{Priority: 1, Match: "example.com.", Spoof: "192.0.2.10"},
			},
		},
	}
}

func TestNewGodNSAppliesDefaultsAndCompilesRules(t *testing.T) {
	config := validGodNSConfig()

	g, err := NewGodNS(config, nil)
	if err != nil {
		t.Fatalf("NewGodNS returned error: %v", err)
	}

	if g.Log == nil {
		t.Fatalf("expected default logger")
	}
	if g.server.Addr != "127.0.0.1:1053" {
		t.Fatalf("server addr = %s, want 127.0.0.1:1053", g.server.Addr)
	}
	if g.server.Net != "udp" {
		t.Fatalf("server net = %s, want udp", g.server.Net)
	}
	if g.client.Net != "udp" {
		t.Fatalf("client net = %s, want udp", g.client.Net)
	}
	if g.client.DialTimeout != 250*time.Millisecond {
		t.Fatalf("dial timeout = %s, want 250ms", g.client.DialTimeout)
	}
	if g.client.ReadTimeout != 500*time.Millisecond {
		t.Fatalf("read timeout = %s, want 500ms", g.client.ReadTimeout)
	}
	if g.client.WriteTimeout != 750*time.Millisecond {
		t.Fatalf("write timeout = %s, want 750ms", g.client.WriteTimeout)
	}
	if len(g.clientConfig.Servers) != 1 || g.clientConfig.Servers[0] != "192.0.2.53" {
		t.Fatalf("upstream servers = %#v, want 192.0.2.53", g.clientConfig.Servers)
	}
	if g.clientConfig.Port != "53" {
		t.Fatalf("upstream port = %s, want 53", g.clientConfig.Port)
	}
	if config.Rules["A"][0].matchGlob == nil {
		t.Fatalf("expected NewGodNS to compile glob rules")
	}
}

func TestNewGodNSRejectsInvalidTimeouts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*GodNSConfig)
	}{
		{
			name: "dial",
			edit: func(config *GodNSConfig) {
				config.Client.DialTimeout = "bad"
			},
		},
		{
			name: "read",
			edit: func(config *GodNSConfig) {
				config.Client.ReadTimeout = "bad"
			},
		},
		{
			name: "write",
			edit: func(config *GodNSConfig) {
				config.Client.WriteTimeout = "bad"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validGodNSConfig()
			tt.edit(config)

			if _, err := NewGodNS(config, newTestLogger()); err == nil {
				t.Fatalf("expected invalid %s timeout to return an error", tt.name)
			}
		})
	}
}

func TestNewGodNSRejectsInvalidRulePattern(t *testing.T) {
	config := validGodNSConfig()
	config.Rules = map[string][]*ReplacementRule{
		"A": {
			{Priority: 1, IsRegExp: true, Match: "[", Spoof: "192.0.2.10"},
		},
	}

	if _, err := NewGodNS(config, newTestLogger()); err == nil {
		t.Fatalf("expected invalid regexp rule to return an error")
	}
}

func TestCompileRulesReturnsPatternErrors(t *testing.T) {
	tests := []struct {
		name string
		rule *ReplacementRule
	}{
		{
			name: "regexp",
			rule: &ReplacementRule{IsRegExp: true, Match: "["},
		},
		{
			name: "glob",
			rule: &ReplacementRule{Match: "["},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := map[string][]*ReplacementRule{
				"A": {tt.rule},
			}
			if err := CompileRules(rules); err == nil {
				t.Fatalf("expected invalid %s pattern to return an error", tt.name)
			}
		})
	}
}

func TestParseConfigFileSuffixesAndErrors(t *testing.T) {
	dir := t.TempDir()
	ymlPath := filepath.Join(dir, "godns.yml")
	unknownPath := filepath.Join(dir, "godns.conf")
	jsonPath := filepath.Join(dir, "bad.json")
	yamlPath := filepath.Join(dir, "bad.yaml")

	validYAML := []byte(`
server:
  net: udp
  interface: 127.0.0.1
  listen_port: 5353
client:
  dial_timeout: 1s
  read_timeout: 2s
  write_timeout: 3s
upstreams:
  - 192.0.2.53
rules:
  A:
    - match: example.com
      spoof: 192.0.2.10
`)
	for _, path := range []string{ymlPath, unknownPath} {
		if err := os.WriteFile(path, validYAML, 0600); err != nil {
			t.Fatalf("write config fixture: %v", err)
		}
	}
	if err := os.WriteFile(jsonPath, []byte(`{"server":`), 0600); err != nil {
		t.Fatalf("write json fixture: %v", err)
	}
	if err := os.WriteFile(yamlPath, []byte("server: ["), 0600); err != nil {
		t.Fatalf("write yaml fixture: %v", err)
	}

	for _, path := range []string{ymlPath, unknownPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			conf, err := ParseConfigFile(path)
			if err != nil {
				t.Fatalf("ParseConfigFile returned error: %v", err)
			}
			if conf.Server.ListenPort != 5353 {
				t.Fatalf("listen port = %d, want 5353", conf.Server.ListenPort)
			}
			if got := conf.Rules["A"][0].Spoof; got != "192.0.2.10" {
				t.Fatalf("A spoof = %s, want 192.0.2.10", got)
			}
		})
	}

	if _, err := ParseConfigFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatalf("expected missing config file to return an error")
	}
	if _, err := ParseConfigFile(jsonPath); err == nil {
		t.Fatalf("expected invalid json config to return an error")
	}
	if _, err := ParseConfigFile(yamlPath); err == nil {
		t.Fatalf("expected invalid yaml config to return an error")
	}
	if _, err := ParseJSONConfig([]byte(`{"server":`)); err == nil {
		t.Fatalf("expected ParseJSONConfig to return an error")
	}
	if _, err := ParseYAMLConfig([]byte("server: [")); err == nil {
		t.Fatalf("expected ParseYAMLConfig to return an error")
	}
}

func TestHandleDNSRequestRejectsEmptyQuestion(t *testing.T) {
	g := &GodNS{Log: newTestLogger()}
	req := new(dns.Msg)
	req.Id = 1234

	writer := newFakeResponseWriter(&net.UDPAddr{IP: net.ParseIP("198.51.100.50"), Port: 53000})
	g.HandleDNSRequest(writer, req)

	if writer.msg == nil {
		t.Fatalf("expected response writer to receive message")
	}
	if writer.msg.Id != req.Id {
		t.Fatalf("response id = %d, want %d", writer.msg.Id, req.Id)
	}
	if writer.msg.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want format error", writer.msg.Rcode)
	}
}

func TestStartReturnsServerError(t *testing.T) {
	g := &GodNS{
		server: &dns.Server{
			Addr: "127.0.0.1:0",
			Net:  "bad-network",
		},
	}

	err := g.Start()
	if err == nil {
		t.Fatalf("expected invalid network to return an error")
	}
	if !strings.Contains(err.Error(), "bad network") {
		t.Fatalf("Start error = %v, want bad network", err)
	}
}

func TestStopReturnsServerErrorWhenNotStarted(t *testing.T) {
	g := &GodNS{
		server: &dns.Server{},
	}

	err := g.Stop()
	if err == nil {
		t.Fatalf("expected stopping an unstarted server to return an error")
	}
	if !strings.Contains(err.Error(), "server not started") {
		t.Fatalf("Stop error = %v, want server not started", err)
	}
}
