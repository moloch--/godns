package godns

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var fuzzSupportedQTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeNS,
	dns.TypeCNAME,
	dns.TypeSOA,
	dns.TypePTR,
	dns.TypeTXT,
	dns.TypeMX,
	dns.TypeSRV,
}

func fuzzDNSName(input string) string {
	input = strings.ToLower(input)
	labels := []string{}
	label := strings.Builder{}
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			label.WriteRune(r)
		case r >= '0' && r <= '9':
			label.WriteRune(r)
		case r == '-':
			if label.Len() > 0 {
				label.WriteRune(r)
			}
		case r == '.':
			if label.Len() > 0 {
				labels = append(labels, strings.TrimRight(label.String(), "-"))
				label.Reset()
			}
		}
		if label.Len() >= 20 {
			labels = append(labels, strings.TrimRight(label.String(), "-"))
			label.Reset()
		}
		if len(labels) >= 6 {
			break
		}
	}
	if label.Len() > 0 && len(labels) < 6 {
		labels = append(labels, strings.TrimRight(label.String(), "-"))
	}

	cleaned := labels[:0]
	for _, label := range labels {
		if label != "" {
			cleaned = append(cleaned, label)
		}
	}
	if len(cleaned) == 0 {
		cleaned = []string{"example"}
	}
	if len(cleaned) == 1 {
		cleaned = append(cleaned, "test")
	}
	return strings.Join(cleaned, ".") + "."
}

func fuzzShortString(input string) string {
	input = strings.ReplaceAll(input, "|", "")
	if len(input) > 256 {
		return input[:256]
	}
	return input
}

func fuzzRemoteAddr(input string) string {
	if ip := net.ParseIP(input); ip != nil {
		return net.JoinHostPort(ip.String(), "53000")
	}
	return "198.51.100.25:53000"
}

func FuzzParseConfigs(f *testing.F) {
	f.Add([]byte(`{"server":{"net":"udp","interface":"127.0.0.1","listen_port":5353},"client":{"dial_timeout":"1s","read_timeout":"2s","write_timeout":"3s"},"upstreams":["192.0.2.53"],"rules":{"A":[{"match":"example.com","spoof":"192.0.2.1"}]}}`))
	f.Add([]byte("server:\n  net: udp\n  listen_port: 5353\nrules:\n  A:\n    - match: example.com\n      spoof: 192.0.2.1\n"))
	f.Add([]byte(`{"server":`))
	f.Add([]byte("server: ["))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		_, _ = ParseJSONConfig(data)
		_, _ = ParseYAMLConfig(data)
	})
}

func FuzzCompileRulesAndMatch(f *testing.F) {
	f.Add("*.example.com", "www.example.com", false, uint8(0))
	f.Add("^www\\.example\\.com\\.$", "www.example.com", true, uint8(0))
	f.Add("[", "www.example.com", true, uint8(0))
	f.Add("example.*", "example.net", false, uint8(1))

	f.Fuzz(func(t *testing.T, match string, query string, isRegex bool, qtypeIndex uint8) {
		if len(match) > 256 || len(query) > 256 {
			t.Skip()
		}
		qtype := fuzzSupportedQTypes[int(qtypeIndex)%len(fuzzSupportedQTypes)]
		ruleType := QueryTypeToString[qtype]
		rules := map[string][]*ReplacementRule{
			ruleType: {
				{
					Priority: 1,
					IsRegExp: isRegex,
					Match:    fuzzShortString(match),
					Spoof:    "192.0.2.10",
				},
			},
		}
		if err := CompileRules(rules); err != nil {
			return
		}

		req := new(dns.Msg)
		req.SetQuestion(fuzzDNSName(query), qtype)
		g := &GodNS{
			Rules: rules,
			Log:   newTestLogger(),
		}
		_, _ = g.matchReplacement(req)
	})
}

func FuzzEvalReplacement(f *testing.F) {
	f.Add("example.com", "192.0.2.10", "198.51.100.25", uint8(0), false, true)
	f.Add("example.com", "2001:db8::1", "198.51.100.25:53000", uint8(1), false, false)
	f.Add("blocked.example", "", "198.51.100.25", uint8(0), true, true)
	f.Add("_service._tcp.example.com", "srv.example.net.", "198.51.100.25", uint8(8), false, true)

	f.Fuzz(func(t *testing.T, qname string, spoof string, remote string, qtypeIndex uint8, block bool, allowSource bool) {
		if len(qname) > 256 || len(spoof) > 256 || len(remote) > 128 {
			t.Skip()
		}
		qtype := fuzzSupportedQTypes[int(qtypeIndex)%len(fuzzSupportedQTypes)]
		ruleType := QueryTypeToString[qtype]
		name := fuzzDNSName(qname)
		rule := &ReplacementRule{
			Priority:      1,
			Match:         name,
			Spoof:         fuzzShortString(spoof),
			Block:         block,
			SpoofMName:    fuzzDNSName(spoof + "mname"),
			SpoofRName:    fuzzDNSName(spoof + "rname"),
			SpoofSerial:   1,
			SpoofRefresh:  2,
			SpoofRetry:    3,
			SpoofExpire:   4,
			SpoofMinTTL:   5,
			SpoofPriority: 1,
			SpoofWeight:   1,
			SpoofPort:     1,
		}
		remoteAddr := fuzzRemoteAddr(remote)
		if allowSource {
			host, _, err := net.SplitHostPort(remoteAddr)
			if err != nil {
				t.Fatalf("normalized remote address %q did not split: %v", remoteAddr, err)
			}
			rule.SourceIPs = []string{host}
		}
		rules := map[string][]*ReplacementRule{
			ruleType: {rule},
		}
		if err := CompileRules(rules); err != nil {
			return
		}

		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		g := &GodNS{
			Rules: rules,
			Log:   newTestLogger(),
		}
		resp := g.evalReplacement(req, remoteAddr)
		if resp != nil {
			_, _ = resp.Pack()
		}
	})
}

func FuzzHandleDNSRequestEmptyQuestion(f *testing.F) {
	f.Add(uint16(0), false, false)
	f.Add(uint16(1234), true, true)

	f.Fuzz(func(t *testing.T, id uint16, recursionDesired bool, checkingDisabled bool) {
		req := new(dns.Msg)
		req.Id = id
		req.RecursionDesired = recursionDesired
		req.CheckingDisabled = checkingDisabled

		writer := newFakeResponseWriter(&net.UDPAddr{IP: net.ParseIP("198.51.100.50"), Port: 53000})
		g := &GodNS{Log: newTestLogger()}
		g.HandleDNSRequest(writer, req)
		if writer.msg == nil {
			t.Fatalf("expected empty-question request to produce a response")
		}
		if writer.msg.Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %d, want format error", writer.msg.Rcode)
		}
	})
}
