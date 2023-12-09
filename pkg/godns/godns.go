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
	"fmt"
	"io"
	"log/slog"
	insecureRand "math/rand"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	// DNSQueryType - Map of replaceable DNS query types
	StringToQueryType = map[string]uint16{
		"A":          dns.TypeA,
		"NS":         dns.TypeNS,
		"CNAME":      dns.TypeCNAME,
		"SOA":        dns.TypeSOA,
		"PTR":        dns.TypePTR,
		"MX":         dns.TypeMX,
		"TXT":        dns.TypeTXT,
		"AAAA":       dns.TypeAAAA,
		"SRV":        dns.TypeSRV,
		"OPT":        dns.TypeOPT,
		"DS":         dns.TypeDS,
		"SSHFP":      dns.TypeSSHFP,
		"RRSIG":      dns.TypeRRSIG,
		"NSEC":       dns.TypeNSEC,
		"DNSKEY":     dns.TypeDNSKEY,
		"NSEC3":      dns.TypeNSEC3,
		"NSEC3PARAM": dns.TypeNSEC3PARAM,
		"TLSA":       dns.TypeTLSA,
		"HIP":        dns.TypeHIP,
		"CDS":        dns.TypeCDS,
		"CDNSKEY":    dns.TypeCDNSKEY,
		"OPENPGPKEY": dns.TypeOPENPGPKEY,
	}

	QueryTypeToString = map[uint16]string{
		dns.TypeA:          "A",
		dns.TypeNS:         "NS",
		dns.TypeCNAME:      "CNAME",
		dns.TypeSOA:        "SOA",
		dns.TypePTR:        "PTR",
		dns.TypeMX:         "MX",
		dns.TypeTXT:        "TXT",
		dns.TypeAAAA:       "AAAA",
		dns.TypeSRV:        "SRV",
		dns.TypeOPT:        "OPT",
		dns.TypeDS:         "DS",
		dns.TypeSSHFP:      "SSHFP",
		dns.TypeRRSIG:      "RRSIG",
		dns.TypeNSEC:       "NSEC",
		dns.TypeDNSKEY:     "DNSKEY",
		dns.TypeNSEC3:      "NSEC3",
		dns.TypeNSEC3PARAM: "NSEC3PARAM",
		dns.TypeTLSA:       "TLSA",
		dns.TypeHIP:        "HIP",
		dns.TypeCDS:        "CDS",
		dns.TypeCDNSKEY:    "CDNSKEY",
		dns.TypeOPENPGPKEY: "OPENPGPKEY",
	}
)

type ReplacementRule struct {
	Priority int    `json:"priority" yaml:"priority"`
	IsRegExp bool   `json:"is_regexp" yaml:"is_regexp"`
	Match    string `json:"match" yaml:"match"`
	Spoof    string `json:"spoof" yaml:"spoof"`

	// Compiled regex
	matchRegex *regexp.Regexp `json:"-" yaml:"-"`
}

type GodNS struct {
	server       *dns.Server
	serverConfig *GodNSConfig

	client       *dns.Client
	clientConfig *dns.ClientConfig

	Rules map[string][]*ReplacementRule
	Log   *slog.Logger
}

// Start - Start the GodNS server
func (g *GodNS) Start() error {
	return g.server.ListenAndServe()
}

// Stop - Stop the GodNS server
func (g *GodNS) Stop() error {
	return g.server.Shutdown()
}

type godNSResult struct {
	Msg *dns.Msg
	Rtt time.Duration
	Err error
}

// HandleDNSRequest - Handle a DNS request
func (g *GodNS) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	msg := &dns.Msg{}
	msg.SetReply(req)

	// Check if we have a valid question
	if len(req.Question) == 0 {
		msg.SetRcode(req, dns.RcodeFormatError)
		writer.WriteMsg(msg)
		return
	}

	// Final Result Channel
	resultChan := make(chan godNSResult, 1)

	// Proxy the request to the upstream resolver, we always send this upstream request
	// first then evaluate if we need to replace the response to minimize time spent
	// waiting for the network
	var upstream string
	upstreamHost := g.clientConfig.Servers[insecureRand.Intn(len(g.clientConfig.Servers))]
	upstream = fmt.Sprintf("%s:%s", upstreamHost, g.clientConfig.Port)
	upstreamWg := sync.WaitGroup{}
	upstreamWg.Add(1)
	upstreamResult := make(chan godNSResult, 1)
	go func(req *dns.Msg, upstream string) {
		defer upstreamWg.Done()
		msg, rtt, err := g.client.Exchange(req, upstream)
		upstreamResult <- godNSResult{Msg: msg, Rtt: rtt, Err: err}
	}(req, upstream)

	// After sending the upstream request, check if we need to replace the response
	// If we do, then we'll ignore the upstream response and just send our own thru
	// the channel. If we don't replace the response then we wait for the upstream
	go func(msg *dns.Msg) {
		started := time.Now()
		replaceMsg := g.replacement(msg)
		if replaceMsg != nil {
			rtt := time.Since(started)
			resultChan <- godNSResult{Msg: replaceMsg, Rtt: rtt, Err: nil}
		}
		upstreamWg.Wait() // Only wait for upstream if we're not replacing the response
		resultChan <- <-upstreamResult
	}(req)

	resp := <-resultChan

	err := writer.WriteMsg(resp.Msg)
	if err != nil {
		g.Log.Error(fmt.Sprintf("Error writing response: %s", err.Error()))
		return
	}
	for index := range resp.Msg.Question {
		qType, ok := QueryTypeToString[resp.Msg.Question[index].Qtype]
		if !ok {
			qType = "UNKNOWN"
		}
		g.Log.Info(fmt.Sprintf("[%s] %s from %s upstream->%s took %s", qType, req.Question[index].Name, writer.RemoteAddr().String(), upstream, resp.Rtt))
	}
}

func (g *GodNS) replacement(req *dns.Msg) *dns.Msg {
	var ok bool
	var rule *ReplacementRule
	if rule, ok = g.matchReplacement(req); !ok {
		return nil
	}

	switch req.Question[0].Qtype {
	case dns.TypeA:
		g.Log.Info(fmt.Sprintf("Spoofing A record for %s to %s", req.Question[0].Name, rule.Spoof))
		return g.spoofA(rule, req)
	case dns.TypeNS:
		g.Log.Info(fmt.Sprintf("Spoofing NS record for %s to %s", req.Question[0].Name, rule.Spoof))
		return g.spoofNS(rule, req)
	case dns.TypeAAAA:
		g.Log.Info(fmt.Sprintf("Spoofing AAAA record for %s to %s", req.Question[0].Name, rule.Spoof))
		return g.spoofAAAA(rule, req)
	}

	g.Log.Warn(fmt.Sprintf("Unsupported DNS record type for spoofing: %s", req.Question[0].String()))
	return nil
}

func (g *GodNS) matchReplacement(req *dns.Msg) (*ReplacementRule, bool) {
	replacementType, ok := QueryTypeToString[req.Question[0].Qtype]
	if !ok {
		return nil, false
	}
	if rules, ok := g.Rules[replacementType]; ok {
		for _, rule := range rules {
			if rule.IsRegExp {
				// RegExp match
				if rule.matchRegex == nil {
					continue
				}
				if rule.matchRegex.MatchString(req.Question[0].Name) {
					return rule, true
				}
			} else {
				// Basic match
				if rule.Match == "*" {
					return rule, true
				}
				qName := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))
				if qName == rule.Match {
					return rule, true
				}
			}
		}
	}
	return nil, false
}

type GodNSConfig struct {
	Server    *ServerConfig `json:"server" yaml:"server"`
	Client    *ClientConfig `json:"client" yaml:"client"`
	Upstreams []string      `json:"upstreams" yaml:"upstreams"`

	// Rules - Map [DNS Query Type]->[ReplacementRules]
	Rules map[string][]*ReplacementRule `json:"rules" yaml:"rules"`
}

type ServerConfig struct {
	Net        string `json:"net" yaml:"net"`
	Host       string `json:"host" yaml:"host"`
	ListenPort uint16 `json:"listen_port" yaml:"listen_port"`
}

type ClientConfig struct {
	Net          string `json:"net" yaml:"net"`
	DialTimeout  string `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout  string `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout string `json:"write_timeout" yaml:"write_timeout"`
}

// NewGodNS - Create a new GodNS instance
func NewGodNS(config *GodNSConfig, logger *slog.Logger) (*GodNS, error) {
	// Create dev null logger if no logger was provided
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Validate client config
	if config.Client.Net == "" {
		logger.Debug("No client network provided, defaulting to udp")
		config.Client.Net = "udp"
	}
	dialTimeout, err := time.ParseDuration(config.Client.DialTimeout)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse dial timeout '%s' %s", config.Client.DialTimeout, err.Error()))
		return nil, err
	}
	readTimeout, err := time.ParseDuration(config.Client.ReadTimeout)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse read timeout '%s' %s", config.Client.ReadTimeout, err.Error()))
		return nil, err
	}
	writeTimeout, err := time.ParseDuration(config.Client.WriteTimeout)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse write timeout '%s' %s", config.Client.WriteTimeout, err.Error()))
		return nil, err
	}

	var clientConfig *dns.ClientConfig
	if len(config.Upstreams) == 0 {
		logger.Debug("No upstreams provided, using system DNS configuration")
		var err error
		clientConfig, err = DNSClientConfig()
		if err != nil {
			return nil, err
		}
	} else {
		logger.Debug("Using provided upstreams from config")
		clientConfig = &dns.ClientConfig{
			Servers: config.Upstreams,
			Port:    "53",
		}
	}
	if len(clientConfig.Servers) == 0 {
		logger.Error("No upstream DNS servers provided")
		return nil, fmt.Errorf("no upstream DNS servers")
	}
	logger.Info(fmt.Sprintf("Upstream DNS resolvers: %s", strings.Join(clientConfig.Servers, ",")))

	// Validate server config
	if config.Server.Net == "" {
		logger.Debug("No server network provided, defaulting to udp")
		config.Server.Net = "udp"
	}

	// Compile rules
	if err := CompileRules(config.Rules); err != nil {
		logger.Error(fmt.Sprintf("failed to compile rule regex: %s", err.Error()))
		return nil, err
	}

	godNS := &GodNS{
		// Server
		server: &dns.Server{
			Addr: fmt.Sprintf("%s:%d", config.Server.Host, config.Server.ListenPort),
			Net:  config.Server.Net,
		},
		serverConfig: config,

		// Client
		client: &dns.Client{
			Net:          config.Client.Net,
			DialTimeout:  dialTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		},
		clientConfig: clientConfig,

		// Rules
		Rules: config.Rules,

		// Logger
		Log: logger,
	}
	dns.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
		godNS.HandleDNSRequest(writer, req)
	})
	return godNS, nil
}

// CompileRules - Compile regex for each rule
func CompileRules(allRules map[string][]*ReplacementRule) error {
	for ruleType := range allRules {
		for _, rule := range allRules[ruleType] {
			if !rule.IsRegExp {
				rule.Match = strings.ToLower(strings.TrimSuffix(rule.Match, "."))
				continue
			}
			regex, err := regexp.Compile(rule.Match)
			if err != nil {
				return err
			}
			rule.matchRegex = regex
		}
		sort.Slice(allRules[ruleType], func(i, j int) bool {
			return allRules[ruleType][i].Priority < allRules[ruleType][j].Priority
		})
	}
	return nil
}
