//go:build !windows

package godns

import "testing"

func TestDNSClientConfigReadsSystemResolverConfig(t *testing.T) {
	conf, err := DNSClientConfig()
	if err != nil {
		t.Skipf("system resolver config is unavailable: %v", err)
	}
	if conf == nil {
		t.Fatalf("expected DNSClientConfig to return a config")
	}
	if conf.Port == "" {
		t.Fatalf("expected resolver config to include a port")
	}
}
