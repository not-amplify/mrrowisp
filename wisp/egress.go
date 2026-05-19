package wisp

import "net"

// EgressPolicy decides whether outbound connections to a given IP are
// permitted. Evaluation order: explicit deny (IPs, CIDRs), explicit allow
// (IPs, CIDRs), kind-based deny (loopback / private / link-local /
// multicast / unspecified) unless the corresponding AllowXxx flag is set.
type EgressPolicy struct {
	AllowLoopback bool
	AllowPrivate  bool

	AllowIPs   map[string]struct{}
	AllowCIDRs []*net.IPNet
	DenyIPs    map[string]struct{}
	DenyCIDRs  []*net.IPNet
}

// PolicyFromConfig builds an EgressPolicy from the Config knobs that
// upstream already exposes (AllowLoopbackIPs, AllowPrivateIPs). The
// caller may extend the returned policy with deny lists.
func PolicyFromConfig(cfg *Config) *EgressPolicy {
	return &EgressPolicy{
		AllowLoopback: cfg.AllowLoopbackIPs,
		AllowPrivate:  cfg.AllowPrivateIPs,
	}
}

// Evaluate returns (allowed, reason). When allowed is true, reason is "".
// When false, reason is one of: "invalid", "deny_ip", "deny_cidr",
// "unspecified", "loopback", "link_local", "private", "multicast".
func (p *EgressPolicy) Evaluate(ip net.IP) (bool, string) {
	if p == nil {
		return true, ""
	}
	if ip == nil {
		return false, "invalid"
	}
	// Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so v4 rules apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if p.DenyIPs != nil {
		if _, ok := p.DenyIPs[ip.String()]; ok {
			return false, "deny_ip"
		}
	}
	for _, n := range p.DenyCIDRs {
		if n.Contains(ip) {
			return false, "deny_cidr"
		}
	}

	explicitAllow := false
	if p.AllowIPs != nil {
		if _, ok := p.AllowIPs[ip.String()]; ok {
			explicitAllow = true
		}
	}
	if !explicitAllow {
		for _, n := range p.AllowCIDRs {
			if n.Contains(ip) {
				explicitAllow = true
				break
			}
		}
	}
	if explicitAllow {
		return true, ""
	}

	if ip.IsUnspecified() {
		return false, "unspecified"
	}
	if ip.IsLoopback() {
		if p.AllowLoopback {
			return true, ""
		}
		return false, "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "link_local"
	}
	if ip.IsPrivate() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "private"
	}
	if ip.IsMulticast() {
		return false, "multicast"
	}
	return true, ""
}
