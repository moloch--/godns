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
	"net"

	"github.com/miekg/dns"
)

func (g *GodNS) spoofA(rule *ReplacementRule, req *dns.Msg) *dns.Msg {
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
