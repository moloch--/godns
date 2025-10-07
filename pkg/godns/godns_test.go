package godns

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCompileRulesCompilesAndSorts(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{
				Priority: 5,
				Match:    "*.example.net",
				IsRegExp: false,
			},
			{
				Priority: 1,
				Match:    "^foo\\..*",
				IsRegExp: true,
			},
			{
				Priority: 3,
				Match:    "test.example.net",
				IsRegExp: false,
			},
		},
	}

	if err := CompileRules(rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	want := []int{1, 3, 5}
	for idx, priority := range want {
		if got := rules["A"][idx].Priority; got != priority {
			t.Fatalf("rule at index %d has priority %d, want %d", idx, got, priority)
		}
	}

	for _, rule := range rules["A"] {
		if rule.IsRegExp && rule.matchRegex == nil {
			t.Fatalf("expected regex rule %q to have compiled expression", rule.Match)
		}
		if !rule.IsRegExp && rule.matchGlob == nil {
			t.Fatalf("expected glob rule %q to have compiled expression", rule.Match)
		}
	}
}

func TestMatchReplacementPrefersHighestPriority(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{
				Priority: 2,
				Match:    "*.example.com",
				IsRegExp: false,
			},
			{
				Priority: 1,
				Match:    "^foo[0-9]+\\.example\\.com\\.$",
				IsRegExp: true,
			},
		},
	}

	if err := CompileRules(rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	g := &GodNS{
		Rules: rules,
		Log:   newTestLogger(),
	}

	req := new(dns.Msg)
	req.SetQuestion("foo123.example.com.", dns.TypeA)
	rule, ok := g.matchReplacement(req)
	if !ok {
		t.Fatalf("expected regex rule to match request")
	}
	if rule.Priority != 1 {
		t.Fatalf("matched rule priority = %d, want 1", rule.Priority)
	}

	req = new(dns.Msg)
	req.SetQuestion("bar.example.com.", dns.TypeA)
	rule, ok = g.matchReplacement(req)
	if !ok {
		t.Fatalf("expected glob rule to match request")
	}
	if rule.Priority != 2 {
		t.Fatalf("matched rule priority = %d, want 2", rule.Priority)
	}

	req = new(dns.Msg)
	req.SetQuestion("baz.example.com.", dns.TypeMX)
	if _, ok = g.matchReplacement(req); ok {
		t.Fatalf("expected no match for MX query type")
	}
}

func TestEvalReplacementHonorsSourceIPs(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{
				Priority:  1,
				Match:     "test.example.com.",
				IsRegExp:  false,
				Spoof:     "192.0.2.55",
				SourceIPs: []string{"10.0.0.1"},
			},
		},
	}

	if err := CompileRules(rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	g := &GodNS{
		Rules: rules,
		Log:   newTestLogger(),
	}

	req := new(dns.Msg)
	req.SetQuestion("test.example.com.", dns.TypeA)

	if resp := g.evalReplacement(req, "192.168.0.10"); resp != nil {
		t.Fatalf("expected replacement to be skipped for disallowed source IP")
	}

	resp := g.evalReplacement(req, "10.0.0.1")
	if resp == nil {
		t.Fatalf("expected replacement for allowed source IP")
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected DNS A answer, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "192.0.2.55" {
		t.Fatalf("spoofed IP = %s, want 192.0.2.55", got)
	}
}

func TestSpoofSRVPopulatesRecordFields(t *testing.T) {
	g := &GodNS{
		Log: newTestLogger(),
	}

	rule := &ReplacementRule{
		Spoof:         "srv.example.com.",
		SpoofPriority: 5,
		SpoofWeight:   10,
		SpoofPort:     443,
	}

	req := new(dns.Msg)
	req.SetQuestion("_service._tcp.example.com.", dns.TypeSRV)

	resp := g.spoofSRV(rule, req)
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}

	srv, ok := resp.Answer[0].(*dns.SRV)
	if !ok {
		t.Fatalf("expected DNS SRV answer, got %T", resp.Answer[0])
	}

	if srv.Priority != rule.SpoofPriority {
		t.Fatalf("srv priority = %d, want %d", srv.Priority, rule.SpoofPriority)
	}
	if srv.Weight != rule.SpoofWeight {
		t.Fatalf("srv weight = %d, want %d", srv.Weight, rule.SpoofWeight)
	}
	if srv.Port != rule.SpoofPort {
		t.Fatalf("srv port = %d, want %d", srv.Port, rule.SpoofPort)
	}
	if srv.Target != rule.Spoof {
		t.Fatalf("srv target = %s, want %s", srv.Target, rule.Spoof)
	}
}

func TestEvalReplacementConcurrentLoad(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{
				Priority: 1,
				Match:    "*.example.com.",
				Spoof:    "192.0.2.42",
			},
		},
	}

	if err := CompileRules(rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	g := &GodNS{
		Rules: rules,
		Log:   newTestLogger(),
	}

	const workers = 32
	const iterationsPerWorker = 256

	errCh := make(chan error, workers*iterationsPerWorker)
	wg := sync.WaitGroup{}
	wg.Add(workers)

	for worker := 0; worker < workers; worker++ {
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < iterationsPerWorker; iter++ {
				req := new(dns.Msg)
				req.SetQuestion(fmt.Sprintf("host-%d.example.com.", iter), dns.TypeA)
				resp := g.evalReplacement(req, "203.0.113.10")
				if resp == nil {
					errCh <- fmt.Errorf("worker %d iteration %d: expected spoofed response, got nil", workerID, iter)
					return
				}
				if len(resp.Answer) != 1 {
					errCh <- fmt.Errorf("worker %d iteration %d: expected 1 answer, got %d", workerID, iter, len(resp.Answer))
					return
				}
				a, ok := resp.Answer[0].(*dns.A)
				if !ok {
					errCh <- fmt.Errorf("worker %d iteration %d: expected A record, got %T", workerID, iter, resp.Answer[0])
					return
				}
				if got := a.A.String(); got != "192.0.2.42" {
					errCh <- fmt.Errorf("worker %d iteration %d: expected spoof 192.0.2.42, got %s", workerID, iter, got)
					return
				}
			}
		}(worker)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

func TestMatchReplacementConcurrentAccess(t *testing.T) {
	rules := map[string][]*ReplacementRule{
		"A": {
			{
				Priority: 1,
				IsRegExp: true,
				Match:    "^api[0-9]+\\.example\\.com\\.$",
				Spoof:    "198.51.100.25",
			},
			{
				Priority: 10,
				IsRegExp: false,
				Match:    "*.example.com.",
				Spoof:    "198.51.100.1",
			},
		},
	}

	if err := CompileRules(rules); err != nil {
		t.Fatalf("CompileRules returned error: %v", err)
	}

	g := &GodNS{
		Rules: rules,
		Log:   newTestLogger(),
	}

	const workers = 16
	const queriesPerWorker = 512

	errCh := make(chan error, workers*queriesPerWorker)
	wg := sync.WaitGroup{}
	wg.Add(workers)

	for worker := 0; worker < workers; worker++ {
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < queriesPerWorker; iter++ {
				req := new(dns.Msg)
				var expectedPriority int
				if iter%2 == 0 {
					req.SetQuestion(fmt.Sprintf("api%d.example.com.", iter), dns.TypeA)
					expectedPriority = 1
				} else {
					req.SetQuestion(fmt.Sprintf("frontend-%d.example.com.", iter), dns.TypeA)
					expectedPriority = 10
				}
				rule, ok := g.matchReplacement(req)
				if !ok {
					errCh <- fmt.Errorf("worker %d iteration %d: expected match", workerID, iter)
					return
				}
				if rule.Priority != expectedPriority {
					errCh <- fmt.Errorf("worker %d iteration %d: priority = %d, want %d", workerID, iter, rule.Priority, expectedPriority)
					return
				}
			}
		}(worker)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

type fakeResponseWriter struct {
	msg        *dns.Msg
	writeErr   error
	remoteAddr net.Addr
	localAddr  net.Addr
	mu         sync.Mutex
}

func newFakeResponseWriter(remote net.Addr) *fakeResponseWriter {
	return &fakeResponseWriter{
		remoteAddr: remote,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	}
}

func (f *fakeResponseWriter) WriteMsg(msg *dns.Msg) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msg = msg.Copy()
	return f.writeErr
}

func (f *fakeResponseWriter) LocalAddr() net.Addr  { return f.localAddr }
func (f *fakeResponseWriter) RemoteAddr() net.Addr { return f.remoteAddr }
func (f *fakeResponseWriter) Close() error         { return nil }
func (f *fakeResponseWriter) TsigStatus() error    { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)  {}
func (f *fakeResponseWriter) Hijack()              {}
func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) (ip string, port string, shutdown func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP listener: %v", err)
	}

	server := &dns.Server{
		PacketConn: conn,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	addr := conn.LocalAddr().(*net.UDPAddr)
	shutdown = func() {
		_ = server.Shutdown()
		_ = conn.Close()
		time.Sleep(10 * time.Millisecond)
	}

	return addr.IP.String(), fmt.Sprintf("%d", addr.Port), shutdown
}

func TestHandleDNSRequestPassThroughARecord(t *testing.T) {
	responseCh := make(chan *dns.Msg, 1)

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    123,
			},
			A: net.ParseIP("203.0.113.99"),
		})

		responseCh <- req.Copy()
		_ = w.WriteMsg(msg)
	})

	ip, port, shutdown := startTestDNSServer(t, upstreamHandler)
	defer shutdown()

	g := &GodNS{
		client: &dns.Client{
			Net:          "udp",
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		},
		clientConfig: &dns.ClientConfig{
			Servers: []string{ip},
			Port:    port,
		},
		Rules: map[string][]*ReplacementRule{},
		Log:   newTestLogger(),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := newFakeResponseWriter(&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 55555})
	g.HandleDNSRequest(writer, req)

	select {
	case upstreamReq := <-responseCh:
		if upstreamReq.Question[0].Name != "example.com." {
			t.Fatalf("upstream question = %s, want example.com.", upstreamReq.Question[0].Name)
		}
	case <-time.After(time.Second):
		t.Fatalf("upstream handler not invoked")
	}

	if writer.msg == nil {
		t.Fatalf("expected response writer to receive message")
	}

	if writer.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("response Rcode = %d, want %d", writer.msg.Rcode, dns.RcodeSuccess)
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(writer.msg.Answer))
	}
	a, ok := writer.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", writer.msg.Answer[0])
	}
	if got := a.A.String(); got != "203.0.113.99" {
		t.Fatalf("spoofed IP = %s, want 203.0.113.99", got)
	}
	if a.Hdr.Ttl != 123 {
		t.Fatalf("TTL = %d, want 123", a.Hdr.Ttl)
	}
}

func TestHandleDNSRequestPassThroughNXDOMAIN(t *testing.T) {
	responseCh := make(chan *dns.Msg, 1)

	upstreamHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Rcode = dns.RcodeNameError

		responseCh <- req.Copy()
		_ = w.WriteMsg(msg)
	})

	ip, port, shutdown := startTestDNSServer(t, upstreamHandler)
	defer shutdown()

	g := &GodNS{
		client: &dns.Client{
			Net:          "udp",
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		},
		clientConfig: &dns.ClientConfig{
			Servers: []string{ip},
			Port:    port,
		},
		Rules: map[string][]*ReplacementRule{},
		Log:   newTestLogger(),
	}

	req := new(dns.Msg)
	req.SetQuestion("does-not-exist.example.", dns.TypeA)

	writer := newFakeResponseWriter(&net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 60000})
	g.HandleDNSRequest(writer, req)

	select {
	case upstreamReq := <-responseCh:
		if upstreamReq.Question[0].Name != "does-not-exist.example." {
			t.Fatalf("upstream question = %s, want does-not-exist.example.", upstreamReq.Question[0].Name)
		}
	case <-time.After(time.Second):
		t.Fatalf("upstream handler not invoked")
	}

	if writer.msg == nil {
		t.Fatalf("expected response writer to receive message")
	}

	if writer.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("response Rcode = %d, want %d", writer.msg.Rcode, dns.RcodeNameError)
	}
	if len(writer.msg.Answer) != 0 {
		t.Fatalf("expected 0 answers for NXDOMAIN, got %d", len(writer.msg.Answer))
	}
}
