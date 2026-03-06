package solver

import "github.com/miekg/dns"

type DNSServer interface {
	ServeDNS(w dns.ResponseWriter, req *dns.Msg)
}
