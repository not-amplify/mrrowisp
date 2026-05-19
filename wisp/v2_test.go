package wisp

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCheckPasswordPlaintext(t *testing.T) {
	if !checkPassword("hunter2", "hunter2") {
		t.Fatal("plain match")
	}
	if checkPassword("hunter2", "hunter3") {
		t.Fatal("plain mismatch should fail")
	}
}

func TestCheckPasswordBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(string(hash), "s3cret") {
		t.Fatal("bcrypt match")
	}
	if checkPassword(string(hash), "wrong") {
		t.Fatal("bcrypt mismatch should fail")
	}
}

func TestCheckPasswordEmpty(t *testing.T) {
	if !checkPassword("", "") {
		t.Fatal("empty == empty should match (constant-time)")
	}
	if checkPassword("", "x") {
		t.Fatal("empty != x")
	}
	if checkPassword("x", "") {
		t.Fatal("x != empty")
	}
}

func TestTwispGateNoAuth(t *testing.T) {
	c := &wispConnection{
		config: &Config{EnableTwisp: true, PasswordAuth: false, CertAuth: false},
		isV2:   true,
	}
	if c.authPassed() {
		t.Fatal("unauthenticated v2 should not pass")
	}
}

func TestTwispGatePasswordAuthSet(t *testing.T) {
	c := &wispConnection{
		config: &Config{EnableTwisp: true, PasswordAuth: true},
		isV2:   true,
	}
	if c.authPassed() {
		t.Fatal("authPassed should default false")
	}
	c.authPassedFlag.Store(true)
	if !c.authPassed() {
		t.Fatal("expected true after store")
	}
}
