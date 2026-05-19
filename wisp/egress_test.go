package wisp

import (
	"net"
	"testing"
)

func mustNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestEgressDeniesPrivateByDefault(t *testing.T) {
	p := &EgressPolicy{}
	cases := []string{
		"10.0.0.1", "192.168.1.5", "172.16.5.5",
		"127.0.0.1", "169.254.1.1",
		"::1", "fc00::1", "fe80::1",
		"0.0.0.0", "224.0.0.1",
	}
	for _, c := range cases {
		ok, _ := p.Evaluate(net.ParseIP(c))
		if ok {
			t.Errorf("expected %s to be denied", c)
		}
	}
}

func TestEgressAllowsPublic(t *testing.T) {
	p := &EgressPolicy{}
	cases := []string{"1.1.1.1", "8.8.8.8", "153.75.225.178", "2001:4860:4860::8888"}
	for _, c := range cases {
		ok, reason := p.Evaluate(net.ParseIP(c))
		if !ok {
			t.Errorf("expected %s to be allowed, got reason %q", c, reason)
		}
	}
}

func TestEgressAllowPrivate(t *testing.T) {
	p := &EgressPolicy{AllowPrivate: true}
	ok, _ := p.Evaluate(net.ParseIP("10.0.0.5"))
	if !ok {
		t.Fatal("expected AllowPrivate to permit 10.0.0.5")
	}
}

func TestEgressAllowLoopback(t *testing.T) {
	p := &EgressPolicy{AllowLoopback: true}
	ok, _ := p.Evaluate(net.ParseIP("127.0.0.1"))
	if !ok {
		t.Fatal("expected AllowLoopback to permit 127.0.0.1")
	}
}

func TestEgressDenyOverridesAllow(t *testing.T) {
	p := &EgressPolicy{
		AllowPrivate: true,
		DenyIPs:      map[string]struct{}{"10.0.0.5": {}},
	}
	ok, reason := p.Evaluate(net.ParseIP("10.0.0.5"))
	if ok || reason != "deny_ip" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}

func TestEgressIPv4MappedV6Unwrap(t *testing.T) {
	p := &EgressPolicy{}
	ok, reason := p.Evaluate(net.ParseIP("::ffff:127.0.0.1"))
	if ok || reason != "loopback" {
		t.Fatalf("got ok=%v reason=%q", ok, reason)
	}
}
