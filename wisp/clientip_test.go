package wisp

import (
	"net"
	"net/http"
	"testing"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestResolveClientIPFromRemoteAddr(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"
	ip := ResolveClientIP(r, nil, nil)
	if ip.String() != "203.0.113.5" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPIgnoresUntrustedHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:1"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	ip := ResolveClientIP(r, nil, []string{"X-Forwarded-For"})
	if ip.String() != "203.0.113.5" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPTrustsHeaderFromTrustedProxy(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	ip := ResolveClientIP(r, trusted, []string{"CF-Connecting-IP"})
	if ip.String() != "198.51.100.7" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPXFFRightmostInTrust(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	ip := ResolveClientIP(r, trusted, []string{"X-Forwarded-For"})
	if ip.String() != "5.6.7.8" {
		t.Fatalf("got %v", ip)
	}
}

func TestResolveClientIPFallbackOnGarbage(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "garbage"
	ip := ResolveClientIP(r, nil, nil)
	if !ip.IsUnspecified() {
		t.Fatalf("got %v", ip)
	}
}
