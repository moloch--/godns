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
	"time"

	"github.com/miekg/dns"
)

var (
	dnsQueryType = map[uint16]string{
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

type GodNS struct {
	server       *dns.Server
	serverConfig *GodNSConfig

	client       *dns.Client
	clientConfig *dns.ClientConfig

	Log *slog.Logger
}

// Start - Start the GodNS server
func (g *GodNS) Start() error {
	return g.server.ListenAndServe()
}

// Stop - Stop the GodNS server
func (g *GodNS) Stop() error {
	return g.server.Shutdown()
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

	// Proxy the request to the upstream resolver
	upstreamHost := g.clientConfig.Servers[insecureRand.Intn(len(g.clientConfig.Servers))]
	upstream := fmt.Sprintf("%s:%s", upstreamHost, g.clientConfig.Port)
	resp, rtt, err := g.client.Exchange(req, upstream)
	if err != nil {
		msg.SetRcode(req, dns.RcodeServerFailure)
		writer.WriteMsg(msg)
		return
	}
	err = writer.WriteMsg(resp)
	if err != nil {
		g.Log.Error(fmt.Sprintf("Error writing response: %s", err.Error()))
		return
	}
	for index := range resp.Question {
		qType, ok := dnsQueryType[resp.Question[index].Qtype]
		if !ok {
			qType = "UNKNOWN"
		}
		g.Log.Info(fmt.Sprintf("[%s] %s from %s upstream->%s took %s", qType, req.Question[index].Name, writer.RemoteAddr().String(), upstream, rtt))
	}
}

type GodNSConfig struct {
	Server *ServerConfig `json:"server" yaml:"server"`
	Client *ClientConfig `json:"client" yaml:"client"`
}

type ServerConfig struct {
	Host       string `json:"host" yaml:"host"`
	ListenPort uint16 `json:"listen_port" yaml:"listen_port"`
	Net        string `json:"net" yaml:"net"`
}

type ClientConfig struct {
	Net          string `json:"net" yaml:"net"`
	DialTimeout  string `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout  string `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout string `json:"write_timeout" yaml:"write_timeout"`
}

// NewGodNS - Create a new GodNS instance
func NewGodNS(config *GodNSConfig, logger *slog.Logger) (*GodNS, error) {

	// Validate client config
	if config.Client.Net == "" {
		config.Client.Net = "udp"
	}
	dialTimeout, err := time.ParseDuration(config.Client.DialTimeout)
	if err != nil {
		return nil, err
	}
	readTimeout, err := time.ParseDuration(config.Client.ReadTimeout)
	if err != nil {
		return nil, err
	}
	writeTimeout, err := time.ParseDuration(config.Client.WriteTimeout)
	if err != nil {
		return nil, err
	}
	clientConfig, err := DNSClientConfig()
	if err != nil {
		return nil, err
	}

	// Validate server config
	if config.Server.Net == "" {
		config.Server.Net = "udp"
	}

	// Create dev null logger if no logger was provided
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	godNS := &GodNS{
		// Server
		server:       &dns.Server{Addr: fmt.Sprintf("%s:%d", config.Server.Host, config.Server.ListenPort), Net: config.Server.Net},
		serverConfig: config,

		// Client
		client: &dns.Client{
			Net:          config.Client.Net,
			DialTimeout:  dialTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		},
		clientConfig: clientConfig,

		// Logger
		Log: logger,
	}
	dns.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
		godNS.HandleDNSRequest(writer, req)
	})
	return godNS, nil
}
