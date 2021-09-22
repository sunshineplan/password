package password

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
)

func TestCompare(t *testing.T) {
	var password = "password"
	hashed, err := GenerateFromPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := Compare("", password, password, false)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	if _, err := Compare("", password, password, true); err == nil {
		t.Error("expected non-nil err; got nil")
	}
	ok, _ = Compare("", hashed, password, false)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = Compare("", hashed, password, true)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = Compare("", hashed, "wrongpassword", true)
	if ok {
		t.Errorf("expected false; got %v", ok)
	}
}

func TestChange(t *testing.T) {
	var oldPassword = "old"
	var newPassword = "new"

	password, err := Change("", oldPassword, oldPassword, newPassword, newPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := Compare("", password, newPassword, true); !ok {
		t.Errorf("expected true; got %v", ok)
	}

	if _, err := Change("", oldPassword, "wrongpassword", newPassword, newPassword, false); !errors.Is(err, ErrIncorrectPassword) {
		t.Errorf("expected ErrIncorrectPassword; got %v", err)
	}

	if _, err := Change("", oldPassword, oldPassword, newPassword, "wrongpassword", false); err != ErrConfirmPasswordNotMatch {
		t.Errorf("expected ErrConfirmPasswordNotMatch; got %v", err)
	}

	if _, err := Change("", oldPassword, oldPassword, oldPassword, oldPassword, false); err != ErrSamePassword {
		t.Errorf("expected ErrSamePassword; got %v", err)
	}

	if _, err := Change("", oldPassword, oldPassword, "", "", false); err != ErrBlankPassword {
		t.Errorf("expected ErrBlankPassword; got %v", err)
	}

	if _, err := Change("", oldPassword, oldPassword, oldPassword, newPassword, false); err != ErrConfirmPasswordNotMatch {
		t.Errorf("expected ErrConfirmPasswordNotMatch; got %v", err)
	}
}

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var password = "password"
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)
	hashed, err := GenerateFromPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := CompareRSA("", password, encrypted, false, priv)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	if _, err := CompareRSA("", password, encrypted, true, priv); err == nil {
		t.Error("expected non-nil err; got nil")
	}
	ok, _ = CompareRSA("", hashed, encrypted, false, priv)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = CompareRSA("", hashed, encrypted, true, priv)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = CompareRSA("", hashed, "wrongpassword", true, priv)
	if ok {
		t.Errorf("expected false; got %v", ok)
	}
}

func TestMaxPasswordAttempts(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := Compare("test1", "password", "wrongpassword", false)
		if !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("expected ErrIncorrectPassword; got %v", err)
		}
	}
	_, err := Compare("test1", "password", "password", false)
	if !errors.Is(err, ErrMaxPasswordAttempts) {
		t.Errorf("expected ErrMaxPasswordAttempts; got %v", err)
	}

	_, err = Compare("test2", "password", "wrongpassword", false)
	if !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("expected ErrIncorrectPassword; got %v", err)
	}
	ok, _ := Compare("test2", "password", "password", false)
	if !ok {
		t.Fatalf("expected true; got %v", ok)
	}
	for i := 0; i < 5; i++ {
		_, err := Compare("test2", "password", "wrongpassword", false)
		if !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("expected ErrIncorrectPassword; got %v", err)
		}
	}
}
