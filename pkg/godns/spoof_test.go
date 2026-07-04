package godns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func newSpoofRequest(qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", qtype)
	req.Id = 0xBEEF
	req.Opcode = dns.OpcodeQuery
	req.Truncated = true
	req.RecursionDesired = true
	req.RecursionAvailable = true
	req.AuthenticatedData = true
	req.CheckingDisabled = true
	req.Compress = true
	return req
}

func assertSpoofHeader(t *testing.T, req, resp *dns.Msg, rcode int) {
	t.Helper()

	if resp == nil {
		t.Fatalf("expected spoof response, got nil")
	}
	if resp.Id != req.Id {
		t.Fatalf("response id = %d, want %d", resp.Id, req.Id)
	}
	if !resp.Response {
		t.Fatalf("expected DNS response flag to be set")
	}
	if !resp.Authoritative {
		t.Fatalf("expected authoritative response")
	}
	if resp.Rcode != rcode {
		t.Fatalf("rcode = %d, want %d", resp.Rcode, rcode)
	}
	if len(resp.Question) != 1 || resp.Question[0] != req.Question[0] {
		t.Fatalf("response question = %#v, want %#v", resp.Question, req.Question)
	}
	if resp.Compress != req.Compress {
		t.Fatalf("compress = %v, want %v", resp.Compress, req.Compress)
	}
}

func TestEvalReplacementSpoofsSupportedRecordTypes(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
		Rules: map[string][]*ReplacementRule{
			"A": {
				{Priority: 1, Match: "example.com.", Spoof: "192.0.2.10"},
			},
			"AAAA": {
				{Priority: 1, Match: "example.com.", Spoof: "2001:db8::10"},
			},
			"NS": {
				{Priority: 1, Match: "example.com.", Spoof: "ns1.example.net."},
			},
			"CNAME": {
				{Priority: 1, Match: "example.com.", Spoof: "alias.example.net."},
			},
			"PTR": {
				{Priority: 1, Match: "example.com.", Spoof: "ptr.example.net."},
			},
			"TXT": {
				{Priority: 1, Match: "example.com.", Spoof: "owned-by-godns"},
			},
			"MX": {
				{Priority: 1, Match: "example.com.", Spoof: "mail.example.net."},
			},
			"SOA": {
				{
					Priority:     1,
					Match:        "example.com.",
					SpoofMName:   "ns1.example.net.",
					SpoofRName:   "hostmaster.example.net.",
					SpoofSerial:  42,
					SpoofRefresh: 43,
					SpoofRetry:   44,
					SpoofExpire:  45,
					SpoofMinTTL:  46,
				},
			},
			"SRV": {
				{
					Priority:      1,
					Match:         "example.com.",
					Spoof:         "srv.example.net.",
					SpoofPriority: 10,
					SpoofWeight:   20,
					SpoofPort:     8443,
				},
			},
		},
	}
	if err := CompileRules(g.Rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	tests := []struct {
		name  string
		qtype uint16
		check func(*testing.T, dns.RR)
	}{
		{
			name:  "A",
			qtype: dns.TypeA,
			check: func(t *testing.T, rr dns.RR) {
				a, ok := rr.(*dns.A)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.A", rr)
				}
				if got := a.A.String(); got != "192.0.2.10" {
					t.Fatalf("A = %s, want 192.0.2.10", got)
				}
			},
		},
		{
			name:  "AAAA",
			qtype: dns.TypeAAAA,
			check: func(t *testing.T, rr dns.RR) {
				aaaa, ok := rr.(*dns.AAAA)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.AAAA", rr)
				}
				if got := aaaa.AAAA.String(); got != "2001:db8::10" {
					t.Fatalf("AAAA = %s, want 2001:db8::10", got)
				}
			},
		},
		{
			name:  "NS",
			qtype: dns.TypeNS,
			check: func(t *testing.T, rr dns.RR) {
				ns, ok := rr.(*dns.NS)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.NS", rr)
				}
				if ns.Ns != "ns1.example.net." {
					t.Fatalf("NS = %s, want ns1.example.net.", ns.Ns)
				}
			},
		},
		{
			name:  "CNAME",
			qtype: dns.TypeCNAME,
			check: func(t *testing.T, rr dns.RR) {
				cname, ok := rr.(*dns.CNAME)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.CNAME", rr)
				}
				if cname.Target != "alias.example.net." {
					t.Fatalf("CNAME = %s, want alias.example.net.", cname.Target)
				}
			},
		},
		{
			name:  "PTR",
			qtype: dns.TypePTR,
			check: func(t *testing.T, rr dns.RR) {
				ptr, ok := rr.(*dns.PTR)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.PTR", rr)
				}
				if ptr.Ptr != "ptr.example.net." {
					t.Fatalf("PTR = %s, want ptr.example.net.", ptr.Ptr)
				}
			},
		},
		{
			name:  "TXT",
			qtype: dns.TypeTXT,
			check: func(t *testing.T, rr dns.RR) {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.TXT", rr)
				}
				if len(txt.Txt) != 1 || txt.Txt[0] != "owned-by-godns" {
					t.Fatalf("TXT = %#v, want owned-by-godns", txt.Txt)
				}
			},
		},
		{
			name:  "MX",
			qtype: dns.TypeMX,
			check: func(t *testing.T, rr dns.RR) {
				mx, ok := rr.(*dns.MX)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.MX", rr)
				}
				if mx.Preference != 10 || mx.Mx != "mail.example.net." {
					t.Fatalf("MX = priority %d host %s, want priority 10 host mail.example.net.", mx.Preference, mx.Mx)
				}
			},
		},
		{
			name:  "SOA",
			qtype: dns.TypeSOA,
			check: func(t *testing.T, rr dns.RR) {
				soa, ok := rr.(*dns.SOA)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.SOA", rr)
				}
				if soa.Ns != "ns1.example.net." || soa.Mbox != "hostmaster.example.net." {
					t.Fatalf("SOA names = %s %s, want configured mname/rname", soa.Ns, soa.Mbox)
				}
				if soa.Serial != 42 || soa.Refresh != 43 || soa.Retry != 44 || soa.Expire != 45 || soa.Minttl != 46 {
					t.Fatalf("SOA timers = %#v, want configured values", soa)
				}
			},
		},
		{
			name:  "SRV",
			qtype: dns.TypeSRV,
			check: func(t *testing.T, rr dns.RR) {
				srv, ok := rr.(*dns.SRV)
				if !ok {
					t.Fatalf("answer type = %T, want *dns.SRV", rr)
				}
				if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 8443 || srv.Target != "srv.example.net." {
					t.Fatalf("SRV = priority %d weight %d port %d target %s, want configured values", srv.Priority, srv.Weight, srv.Port, srv.Target)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSpoofRequest(tt.qtype)
			resp := g.evalReplacement(req, "198.51.100.25:53000")
			assertSpoofHeader(t, req, resp, dns.RcodeSuccess)
			if len(resp.Answer) != 1 {
				t.Fatalf("answer count = %d, want 1", len(resp.Answer))
			}
			if resp.Answer[0].Header().Name != req.Question[0].Name {
				t.Fatalf("answer name = %s, want %s", resp.Answer[0].Header().Name, req.Question[0].Name)
			}
			if resp.Answer[0].Header().Rrtype != tt.qtype {
				t.Fatalf("answer type = %d, want %d", resp.Answer[0].Header().Rrtype, tt.qtype)
			}
			tt.check(t, resp.Answer[0])
		})
	}
}

func TestEvalReplacementBlockReturnsNXDomainResponse(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
		Rules: map[string][]*ReplacementRule{
			"A": {
				{Priority: 1, Match: "blocked.example.", Block: true},
			},
		},
	}
	if err := CompileRules(g.Rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	req := newSpoofRequest(dns.TypeA)
	req.Question[0].Name = "blocked.example."
	resp := g.evalReplacement(req, "198.51.100.25:53000")

	assertSpoofHeader(t, req, resp, dns.RcodeNameError)
	if len(resp.Answer) != 0 {
		t.Fatalf("answer count = %d, want 0", len(resp.Answer))
	}
}

func TestEvalReplacementHonorsSourceIPHostPort(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
		Rules: map[string][]*ReplacementRule{
			"A": {
				{
					Priority:  1,
					Match:     "source.example.",
					Spoof:     "192.0.2.44",
					SourceIPs: []string{"198.51.100.25"},
				},
			},
		},
	}
	if err := CompileRules(g.Rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	req := newSpoofRequest(dns.TypeA)
	req.Question[0].Name = "source.example."
	resp := g.evalReplacement(req, "198.51.100.25:53000")
	if resp == nil {
		t.Fatalf("expected replacement for allowed host:port remote address")
	}

	if resp := g.evalReplacement(req, "198.51.100.26:53000"); resp != nil {
		t.Fatalf("expected replacement to be skipped for disallowed host:port remote address")
	}
}

func TestEvalReplacementUnsupportedCompiledTypeReturnsNil(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
		Rules: map[string][]*ReplacementRule{
			"DNSKEY": {
				{Priority: 1, Match: "example.com.", Spoof: "ignored"},
			},
		},
	}
	if err := CompileRules(g.Rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	req := newSpoofRequest(dns.TypeDNSKEY)
	if resp := g.evalReplacement(req, "198.51.100.25:53000"); resp != nil {
		t.Fatalf("expected unsupported spoof type to return nil, got %#v", resp)
	}
}

func TestMatchReplacementSkipsUncompiledRules(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
		Rules: map[string][]*ReplacementRule{
			"A": {
				{Priority: 1, IsRegExp: true, Match: "^example\\.com\\.$", Spoof: "192.0.2.1"},
				{Priority: 2, Match: "example.com.", Spoof: "192.0.2.2"},
			},
		},
	}

	req := newSpoofRequest(dns.TypeA)
	if rule, ok := g.matchReplacement(req); ok {
		t.Fatalf("expected uncompiled rules to be skipped, matched %#v", rule)
	}
}

func TestSpoofInvalidIPValuesDoNotPanic(t *testing.T) {
	g := &GodNS{Log: newTestLogger()}

	req := newSpoofRequest(dns.TypeA)
	aResp := g.spoofA(&ReplacementRule{Spoof: "not-an-ip"}, req)
	assertSpoofHeader(t, req, aResp, dns.RcodeSuccess)
	a := aResp.Answer[0].(*dns.A)
	if a.A != nil {
		t.Fatalf("invalid A spoof parsed to %s, want nil", a.A)
	}

	req = newSpoofRequest(dns.TypeAAAA)
	aaaaResp := g.spoofAAAA(&ReplacementRule{Spoof: "not-an-ip"}, req)
	assertSpoofHeader(t, req, aaaaResp, dns.RcodeSuccess)
	aaaa := aaaaResp.Answer[0].(*dns.AAAA)
	if aaaa.AAAA != nil {
		t.Fatalf("invalid AAAA spoof parsed to %s, want nil", aaaa.AAAA)
	}
}

func TestSpoofSRVAllowsZeroValues(t *testing.T) {
	g := &GodNS{Log: newTestLogger()}
	req := newSpoofRequest(dns.TypeSRV)

	resp := g.spoofSRV(&ReplacementRule{Spoof: "srv.example.net."}, req)
	assertSpoofHeader(t, req, resp, dns.RcodeSuccess)

	srv := resp.Answer[0].(*dns.SRV)
	if srv.Priority != 0 || srv.Weight != 0 || srv.Port != 0 || srv.Target != "srv.example.net." {
		t.Fatalf("SRV = priority %d weight %d port %d target %s, want zero values and configured target", srv.Priority, srv.Weight, srv.Port, srv.Target)
	}
}

func TestStringQueryTypeMapsRoundTrip(t *testing.T) {
	for name, qtype := range StringToQueryType {
		if got, ok := QueryTypeToString[qtype]; !ok || got != name {
			t.Fatalf("query type %s (%d) reverse map = %q, %v", name, qtype, got, ok)
		}
	}
}

func TestSpoofAUsesIPv4Form(t *testing.T) {
	g := &GodNS{Log: newTestLogger()}
	req := newSpoofRequest(dns.TypeA)

	resp := g.spoofA(&ReplacementRule{Spoof: "::ffff:192.0.2.99"}, req)
	assertSpoofHeader(t, req, resp, dns.RcodeSuccess)
	a := resp.Answer[0].(*dns.A)
	if got := net.IP(a.A).String(); got != "192.0.2.99" {
		t.Fatalf("A = %s, want IPv4 form 192.0.2.99", got)
	}
}
