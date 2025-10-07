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
	"net"

	"github.com/miekg/dns"
)

func (g *GodNS) spoofNX(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           false,
			Opcode:             req.Opcode,
			Authoritative:      false,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              dns.RcodeNameError,
		},
		Compress: req.Compress,
		Question: req.Question,
	}
}

func (g *GodNS) spoofA(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	if net.ParseIP(rule.Spoof).To4() == nil {
		g.Log.Warn(fmt.Sprintf("A rule contains invalid IPv4 address: %s", rule.Spoof))
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: net.ParseIP(rule.Spoof).To4(),
			},
		},
	}
}

func (g *GodNS) spoofNS(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ns: rule.Spoof,
			},
		},
	}
}

func (g *GodNS) spoofCNAME(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Target: rule.Spoof,
			},
		},
	}
}

func (g *GodNS) spoofSOA(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ns:      rule.SpoofMName,
				Mbox:    rule.SpoofRName,
				Serial:  rule.SpoofSerial,
				Refresh: rule.SpoofRefresh,
				Retry:   rule.SpoofRetry,
				Expire:  rule.SpoofExpire,
				Minttl:  rule.SpoofMinTTL,
			},
		},
	}
}

func (g *GodNS) spoofPTR(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.PTR{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ptr: rule.Spoof,
			},
		},
	}
}

func (g *GodNS) spoofMX(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.MX{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Preference: 10,
				Mx:         rule.Spoof,
			},
		},
	}
}

func (g *GodNS) spoofTXT(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: []string{rule.Spoof},
			},
		},
	}
}

func (g *GodNS) spoofAAAA(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	if net.ParseIP(rule.Spoof).To16() == nil {
		g.Log.Warn(fmt.Sprintf("AAAA rule contains invalid IPv6 address: %s", rule.Spoof))
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				AAAA: net.ParseIP(rule.Spoof).To16(),
			},
		},
	}

}

func (g *GodNS) spoofSRV(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
	if rule.SpoofPriority == 0 {
		g.Log.Warn(fmt.Sprintf("SRV rule contains invalid spoof priority: %d", rule.SpoofPriority))
	}
	if rule.SpoofWeight == 0 {
		g.Log.Warn(fmt.Sprintf("SRV rule contains invalid spoof weight: %d", rule.SpoofWeight))
	}
	if rule.SpoofPort == 0 {
		g.Log.Warn(fmt.Sprintf("SRV rule contains invalid spoof port: %d", rule.SpoofPort))
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           true,
			Opcode:             req.Opcode,
			Authoritative:      true,
			Truncated:          req.Truncated,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: req.RecursionAvailable,
			AuthenticatedData:  req.AuthenticatedData,
			CheckingDisabled:   req.CheckingDisabled,
			Rcode:              dns.RcodeSuccess,
		},
		Compress: req.Compress,
		Question: req.Question,
		Answer: []dns.RR{
			&dns.SRV{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Priority: rule.SpoofPriority,
				Weight:   rule.SpoofWeight,
				Port:     rule.SpoofPort,
				Target:   rule.Spoof,
			},
		},
	}
}
