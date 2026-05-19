package wisp

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCheckPasswordPlaintext(t *testing.T) {
	if !checkPassword(nil, "hunter2", "hunter2") {
		t.Fatal("plain match")
	}
	if checkPassword(nil, "hunter2", "hunter3") {
		t.Fatal("plain mismatch should fail")
	}
}

func TestCheckPasswordBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(nil, string(hash), "s3cret") {
		t.Fatal("bcrypt match")
	}
	if checkPassword(nil, string(hash), "wrong") {
		t.Fatal("bcrypt mismatch should fail")
	}
}

func TestCheckPasswordLengthMismatch(t *testing.T) {
	if checkPassword(nil, "abc", "abcd") {
		t.Fatal("length mismatch must fail")
	}
}
