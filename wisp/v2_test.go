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
