package password

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	var password = "password"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if err := Compare("", password, password); err != nil {
		t.Error(err)
	}
	if err := CompareHashAndPassword("", hashed, password); err != nil {
		t.Error(err)
	}
	if err := CompareHashAndPassword("", hashed, "wrongpassword"); err == nil {
		t.Error("expected non-nil err; got nil")
	}
}

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := New(24*time.Hour, 5, priv)
	var password = "password"
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Compare("", password, encrypted); err != nil {
		t.Error(err)
	}
	if err := p.CompareHashAndPassword("", password, encrypted); err == nil {
		t.Error("expected non-nil err; got nil")
	}
	if err := p.Compare("", hashed, encrypted); err == nil {
		t.Error("expected non-nil err; got nil")
	}
	if err := p.CompareHashAndPassword("", hashed, encrypted); err != nil {
		t.Error(err)
	}
	if err := p.CompareHashAndPassword("", hashed, "wrongpassword"); err == nil {
		t.Error("expected non-nil err; got nil")
	}
}

func TestMaxPasswordAttempts(t *testing.T) {
	p := New(24*time.Hour, 5, nil)
	type info struct {
		id   string
		info any
	}
	for i := 0; i < 5; i++ {
		if err := p.Compare(info{"test1", nil}, "password", "wrongpassword"); !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("expected ErrIncorrectPassword; got %v", err)
		}
	}
	if err := p.Compare(info{"test1", nil}, "password", "password"); !errors.Is(err, ErrMaxPasswordAttempts) {
		t.Errorf("expected ErrMaxPasswordAttempts; got %v", err)
	}

	if err := p.Compare(info{"test1", "test2"}, "password", "wrongpassword"); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("expected ErrIncorrectPassword; got %v", err)
	}
	if err := p.Compare(info{"test1", "test2"}, "password", "password"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := p.Compare(info{"test1", "test2"}, "password", "wrongpassword"); !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("expected ErrIncorrectPassword; got %v", err)
		}
	}
	if err := p.Compare(info{"test1", "test2"}, "password", "password"); !errors.Is(err, ErrMaxPasswordAttempts) {
		t.Errorf("expected ErrMaxPasswordAttempts; got %v", err)
	}
}
