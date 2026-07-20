package godns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	e2eTimeout     = 2 * time.Second
	e2eUpstreamTTL = 300
)

type e2eObservedQuery struct {
	name  string
	qtype uint16
}

func startE2EUpstream(t *testing.T, network string) (string, <-chan e2eObservedQuery) {
	t.Helper()

	queries := make(chan e2eObservedQuery, 128)
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			msg := new(dns.Msg)
			msg.SetRcode(req, dns.RcodeFormatError)
			_ = writer.WriteMsg(msg)
			return
		}

		question := req.Question[0]
		queries <- e2eObservedQuery{name: question.Name, qtype: question.Qtype}
		_ = writer.WriteMsg(e2eUpstreamResponse(req))
	})

	server := &dns.Server{Handler: handler}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	serveErr := make(chan error, 1)
	var address string

	switch network {
	case "udp":
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			skipIfLocalNetworkUnavailable(t, err)
			t.Fatalf("listen for UDP upstream: %v", err)
		}
		server.PacketConn = packetConn
		address = packetConn.LocalAddr().String()
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			skipIfLocalNetworkUnavailable(t, err)
			t.Fatalf("listen for TCP upstream: %v", err)
		}
		server.Listener = listener
		address = listener.Addr().String()
	default:
		t.Fatalf("unsupported test network %q", network)
	}

	go func() {
		serveErr <- server.ActivateAndServe()
	}()

	select {
	case <-started:
	case err := <-serveErr:
		t.Fatalf("start %s upstream DNS server: %v", network, err)
	case <-time.After(e2eTimeout):
		t.Fatalf("timed out starting %s upstream DNS server", network)
	}

	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("stop %s upstream DNS server: %v", network, err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("%s upstream DNS server returned an error: %v", network, err)
			}
		case <-time.After(e2eTimeout):
			t.Errorf("timed out waiting for %s upstream DNS server to stop", network)
		}
	})

	return address, queries
}

func e2eUpstreamResponse(req *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.RecursionAvailable = true

	question := req.Question[0]
	if question.Name == "missing.proxy.e2e.test." {
		msg.Rcode = dns.RcodeNameError
		return msg
	}

	header := dns.RR_Header{
		Name:   question.Name,
		Rrtype: question.Qtype,
		Class:  dns.ClassINET,
		Ttl:    e2eUpstreamTTL,
	}

	switch question.Qtype {
	case dns.TypeA:
		msg.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("203.0.113.53").To4()}}
	case dns.TypeAAAA:
		msg.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::53")}}
	case dns.TypeNS:
		msg.Answer = []dns.RR{&dns.NS{Hdr: header, Ns: "ns.upstream.e2e.test."}}
	case dns.TypeCNAME:
		msg.Answer = []dns.RR{&dns.CNAME{Hdr: header, Target: "alias.upstream.e2e.test."}}
	case dns.TypeSOA:
		msg.Answer = []dns.RR{&dns.SOA{
			Hdr:     header,
			Ns:      "ns.upstream.e2e.test.",
			Mbox:    "hostmaster.upstream.e2e.test.",
			Serial:  9001,
			Refresh: 9002,
			Retry:   9003,
			Expire:  9004,
			Minttl:  9005,
		}}
	case dns.TypePTR:
		msg.Answer = []dns.RR{&dns.PTR{Hdr: header, Ptr: "ptr.upstream.e2e.test."}}
	case dns.TypeMX:
		msg.Answer = []dns.RR{&dns.MX{Hdr: header, Preference: 25, Mx: "mail.upstream.e2e.test."}}
	case dns.TypeTXT:
		msg.Answer = []dns.RR{&dns.TXT{Hdr: header, Txt: []string{"from-upstream"}}}
	case dns.TypeSRV:
		msg.Answer = []dns.RR{&dns.SRV{
			Hdr:      header,
			Priority: 30,
			Weight:   40,
			Port:     9443,
			Target:   "srv.upstream.e2e.test.",
		}}
	default:
		msg.Rcode = dns.RcodeNotImplemented
	}

	return msg
}

func startGodNSE2E(t *testing.T, network, upstreamAddress string, rules map[string][]*ReplacementRule) string {
	t.Helper()

	upstreamHost, upstreamPort, err := net.SplitHostPort(upstreamAddress)
	if err != nil {
		t.Fatalf("split upstream address %q: %v", upstreamAddress, err)
	}

	listenPort := reserveE2EPort(t, network)
	config := &GodNSConfig{
		Server: &ServerConfig{
			Net:        network,
			Host:       "127.0.0.1",
			ListenPort: listenPort,
		},
		Client: &ClientConfig{
			Net:          network,
			DialTimeout:  e2eTimeout.String(),
			ReadTimeout:  e2eTimeout.String(),
			WriteTimeout: e2eTimeout.String(),
		},
		Upstreams: []string{upstreamHost},
		Rules:     rules,
	}

	server, err := NewGodNS(config, newTestLogger())
	if err != nil {
		t.Fatalf("create GodNS server: %v", err)
	}
	// Production upstreams default to port 53. The isolated upstream uses an
	// ephemeral port so the test never needs elevated privileges or Internet DNS.
	server.clientConfig.Port = upstreamPort

	started := make(chan struct{})
	server.server.NotifyStartedFunc = func() { close(started) }
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Start()
	}()

	select {
	case <-started:
	case err := <-serveErr:
		t.Fatalf("start GodNS %s listener: %v", network, err)
	case <-time.After(e2eTimeout):
		t.Fatalf("timed out starting GodNS %s listener", network)
	}

	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("stop GodNS %s listener: %v", network, err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("GodNS %s listener returned an error: %v", network, err)
			}
		case <-time.After(e2eTimeout):
			t.Errorf("timed out waiting for GodNS %s listener to stop", network)
		}
	})

	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort)))
}

func reserveE2EPort(t *testing.T, network string) uint16 {
	t.Helper()

	var address net.Addr
	switch network {
	case "udp":
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			skipIfLocalNetworkUnavailable(t, err)
			t.Fatalf("reserve UDP port: %v", err)
		}
		address = packetConn.LocalAddr()
		if err := packetConn.Close(); err != nil {
			t.Fatalf("release reserved UDP port: %v", err)
		}
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			skipIfLocalNetworkUnavailable(t, err)
			t.Fatalf("reserve TCP port: %v", err)
		}
		address = listener.Addr()
		if err := listener.Close(); err != nil {
			t.Fatalf("release reserved TCP port: %v", err)
		}
	default:
		t.Fatalf("unsupported test network %q", network)
	}

	_, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatalf("split reserved address %q: %v", address.String(), err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("parse reserved port %q: %v", portText, err)
	}
	return uint16(port)
}

func skipIfLocalNetworkUnavailable(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("sandbox does not allow binding a local DNS listener: %v", err)
	}
}

func exchangeE2EQuery(t *testing.T, network, serverAddress, name string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	client := &dns.Client{
		Net:          network,
		DialTimeout:  e2eTimeout,
		ReadTimeout:  e2eTimeout,
		WriteTimeout: e2eTimeout,
	}
	resp, _, err := client.Exchange(req, serverAddress)
	if err != nil {
		t.Fatalf("exchange %s %s query with GodNS at %s: %v", network, dns.TypeToString[qtype], serverAddress, err)
	}
	if resp == nil {
		t.Fatalf("exchange %s %s query returned a nil response", network, dns.TypeToString[qtype])
	}
	if !resp.Response {
		t.Fatalf("DNS message is not marked as a response: %#v", resp.MsgHdr)
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != name || resp.Question[0].Qtype != qtype {
		t.Fatalf("response question = %#v, want %s %s", resp.Question, name, dns.TypeToString[qtype])
	}
	return resp
}

func assertE2EUpstreamQuery(t *testing.T, queries <-chan e2eObservedQuery, name string, qtype uint16) {
	t.Helper()
	select {
	case query := <-queries:
		if query.name != name || query.qtype != qtype {
			t.Fatalf("upstream query = %s %s, want %s %s", query.name, dns.TypeToString[query.qtype], name, dns.TypeToString[qtype])
		}
	case <-time.After(e2eTimeout):
		t.Fatalf("upstream did not receive %s %s query", name, dns.TypeToString[qtype])
	}
}

func assertE2EResponse(t *testing.T, resp *dns.Msg, rcode int, authoritative bool, expectedRR string) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Fatalf("response rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
	}
	if resp.Authoritative != authoritative {
		t.Fatalf("response authoritative = %v, want %v", resp.Authoritative, authoritative)
	}
	if expectedRR == "" {
		if len(resp.Answer) != 0 {
			t.Fatalf("response answers = %#v, want none", resp.Answer)
		}
		return
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("response answer count = %d, want 1: %#v", len(resp.Answer), resp.Answer)
	}
	want, err := dns.NewRR(expectedRR)
	if err != nil {
		t.Fatalf("parse expected resource record %q: %v", expectedRR, err)
	}
	if got := resp.Answer[0].String(); got != want.String() {
		t.Fatalf("response answer = %q, want %q", got, want.String())
	}
}

func TestGodNSEndToEndProxiesDNSQueries(t *testing.T) {
	tests := []struct {
		name       string
		qtype      uint16
		expectedRR string
		rcode      int
	}{
		{
			name:       "a.proxy.e2e.test.",
			qtype:      dns.TypeA,
			expectedRR: "a.proxy.e2e.test. 300 IN A 203.0.113.53",
			rcode:      dns.RcodeSuccess,
		},
		{
			name:       "aaaa.proxy.e2e.test.",
			qtype:      dns.TypeAAAA,
			expectedRR: "aaaa.proxy.e2e.test. 300 IN AAAA 2001:db8::53",
			rcode:      dns.RcodeSuccess,
		},
		{
			name:       "txt.proxy.e2e.test.",
			qtype:      dns.TypeTXT,
			expectedRR: `txt.proxy.e2e.test. 300 IN TXT "from-upstream"`,
			rcode:      dns.RcodeSuccess,
		},
		{
			name:       "_service._tcp.proxy.e2e.test.",
			qtype:      dns.TypeSRV,
			expectedRR: "_service._tcp.proxy.e2e.test. 300 IN SRV 30 40 9443 srv.upstream.e2e.test.",
			rcode:      dns.RcodeSuccess,
		},
		{
			name:  "missing.proxy.e2e.test.",
			qtype: dns.TypeA,
			rcode: dns.RcodeNameError,
		},
	}

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			upstreamAddress, upstreamQueries := startE2EUpstream(t, network)
			godNSAddress := startGodNSE2E(t, network, upstreamAddress, map[string][]*ReplacementRule{})

			for _, tt := range tests {
				t.Run(fmt.Sprintf("%s/%s", dns.TypeToString[tt.qtype], tt.name), func(t *testing.T) {
					resp := exchangeE2EQuery(t, network, godNSAddress, tt.name, tt.qtype)
					assertE2EResponse(t, resp, tt.rcode, false, tt.expectedRR)
					assertE2EUpstreamQuery(t, upstreamQueries, tt.name, tt.qtype)
				})
			}
		})
	}
}

func TestGodNSEndToEndAppliesReplacementRules(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{Priority: 10, Match: "exact.replace.e2e.test", Spoof: "192.0.2.10"},
			{Priority: 10, Match: "*.glob.replace.e2e.test", Spoof: "192.0.2.11"},
			{Priority: 10, IsRegExp: true, Match: `^api[0-9]+\.regex\.replace\.e2e\.test\.$`, Spoof: "192.0.2.12"},
			{Priority: 10, Match: "allowed-source.replace.e2e.test", SourceIPs: []string{"127.0.0.1"}, Spoof: "192.0.2.13"},
			{Priority: 10, Match: "denied-source.replace.e2e.test", SourceIPs: []string{"192.0.2.200"}, Spoof: "192.0.2.14"},
			{Priority: 20, Match: "priority.replace.e2e.test", Spoof: "192.0.2.15"},
			{Priority: 1, IsRegExp: true, Match: `^priority\.replace\.e2e\.test\.$`, Spoof: "192.0.2.16"},
			{Priority: 10, Match: "blocked.replace.e2e.test", Block: true},
		},
		"AAAA": {
			{Priority: 10, Match: "aaaa.replace.e2e.test", Spoof: "2001:db8::10"},
		},
		"NS": {
			{Priority: 10, Match: "ns.replace.e2e.test", Spoof: "ns.replaced.e2e.test."},
		},
		"CNAME": {
			{Priority: 10, Match: "cname.replace.e2e.test", Spoof: "alias.replaced.e2e.test."},
		},
		"SOA": {
			{
				Priority:     10,
				Match:        "soa.replace.e2e.test",
				SpoofMName:   "ns.replaced.e2e.test.",
				SpoofRName:   "hostmaster.replaced.e2e.test.",
				SpoofSerial:  42,
				SpoofRefresh: 43,
				SpoofRetry:   44,
				SpoofExpire:  45,
				SpoofMinTTL:  46,
			},
		},
		"PTR": {
			{Priority: 10, Match: "10.2.0.192.in-addr.arpa", Spoof: "ptr.replaced.e2e.test."},
		},
		"MX": {
			{Priority: 10, Match: "mx.replace.e2e.test", Spoof: "mail.replaced.e2e.test."},
		},
		"TXT": {
			{Priority: 10, Match: "txt.replace.e2e.test", Spoof: "from-godns"},
		},
		"SRV": {
			{
				Priority:      10,
				Match:         "_service._tcp.replace.e2e.test",
				Spoof:         "srv.replaced.e2e.test.",
				SpoofPriority: 10,
				SpoofWeight:   20,
				SpoofPort:     8443,
			},
		},
	}

	tests := []struct {
		testName      string
		name          string
		qtype         uint16
		rcode         int
		authoritative bool
		expectedRR    string
	}{
		{
			testName:      "exact glob A rule",
			name:          "exact.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "exact.replace.e2e.test. 0 IN A 192.0.2.10",
		},
		{
			testName:      "wildcard glob A rule",
			name:          "www.glob.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "www.glob.replace.e2e.test. 0 IN A 192.0.2.11",
		},
		{
			testName:      "regexp A rule",
			name:          "api42.regex.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "api42.regex.replace.e2e.test. 0 IN A 192.0.2.12",
		},
		{
			testName:      "source IP allowed",
			name:          "allowed-source.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "allowed-source.replace.e2e.test. 0 IN A 192.0.2.13",
		},
		{
			testName:      "source IP denied falls through",
			name:          "denied-source.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: false,
			expectedRR:    "denied-source.replace.e2e.test. 300 IN A 203.0.113.53",
		},
		{
			testName:      "higher priority rule wins",
			name:          "priority.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "priority.replace.e2e.test. 0 IN A 192.0.2.16",
		},
		{
			testName:      "block rule returns NXDOMAIN",
			name:          "blocked.replace.e2e.test.",
			qtype:         dns.TypeA,
			rcode:         dns.RcodeNameError,
			authoritative: true,
		},
		{
			testName:      "AAAA replacement",
			name:          "aaaa.replace.e2e.test.",
			qtype:         dns.TypeAAAA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "aaaa.replace.e2e.test. 0 IN AAAA 2001:db8::10",
		},
		{
			testName:      "NS replacement",
			name:          "ns.replace.e2e.test.",
			qtype:         dns.TypeNS,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "ns.replace.e2e.test. 0 IN NS ns.replaced.e2e.test.",
		},
		{
			testName:      "CNAME replacement",
			name:          "cname.replace.e2e.test.",
			qtype:         dns.TypeCNAME,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "cname.replace.e2e.test. 0 IN CNAME alias.replaced.e2e.test.",
		},
		{
			testName:      "SOA replacement",
			name:          "soa.replace.e2e.test.",
			qtype:         dns.TypeSOA,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "soa.replace.e2e.test. 0 IN SOA ns.replaced.e2e.test. hostmaster.replaced.e2e.test. 42 43 44 45 46",
		},
		{
			testName:      "PTR replacement",
			name:          "10.2.0.192.in-addr.arpa.",
			qtype:         dns.TypePTR,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "10.2.0.192.in-addr.arpa. 0 IN PTR ptr.replaced.e2e.test.",
		},
		{
			testName:      "MX replacement",
			name:          "mx.replace.e2e.test.",
			qtype:         dns.TypeMX,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "mx.replace.e2e.test. 0 IN MX 10 mail.replaced.e2e.test.",
		},
		{
			testName:      "TXT replacement",
			name:          "txt.replace.e2e.test.",
			qtype:         dns.TypeTXT,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    `txt.replace.e2e.test. 0 IN TXT "from-godns"`,
		},
		{
			testName:      "SRV replacement",
			name:          "_service._tcp.replace.e2e.test.",
			qtype:         dns.TypeSRV,
			rcode:         dns.RcodeSuccess,
			authoritative: true,
			expectedRR:    "_service._tcp.replace.e2e.test. 0 IN SRV 10 20 8443 srv.replaced.e2e.test.",
		},
	}

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			upstreamAddress, upstreamQueries := startE2EUpstream(t, network)
			godNSAddress := startGodNSE2E(t, network, upstreamAddress, rules)

			for _, tt := range tests {
				t.Run(tt.testName, func(t *testing.T) {
					resp := exchangeE2EQuery(t, network, godNSAddress, tt.name, tt.qtype)
					assertE2EResponse(t, resp, tt.rcode, tt.authoritative, tt.expectedRR)
					// GodNS deliberately starts an upstream exchange before evaluating
					// replacement rules. Confirm that behavior through the real socket.
					assertE2EUpstreamQuery(t, upstreamQueries, tt.name, tt.qtype)
				})
			}
		})
	}
}
