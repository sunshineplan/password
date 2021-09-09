package password

import "testing"

func TestCompare(t *testing.T) {
	var password = "password"
	var hashed = "$2a$04$T6zSWlGSRxSuA.BgTvxmmuOm3AyECdxg6/Tl3l9PouBksxQhek0qK"

	ok, _ := Compare(password, password, false)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	_, err := Compare(password, password, true)
	if err == nil {
		t.Error("expected non-nil err; got nil")
	}
	ok, _ = Compare(hashed, password, false)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = Compare(hashed, password, true)
	if !ok {
		t.Errorf("expected true; got %v", ok)
	}
	ok, _ = Compare(hashed, "wrongpassword", true)
	if ok {
		t.Errorf("expected false; got %v", ok)
	}
}

func TestChange(t *testing.T) {
	var oldPassword = "old"
	var newPassword = "new"

	password, err := Change(oldPassword, oldPassword, newPassword, newPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := Compare(password, newPassword, true); !ok {
		t.Errorf("expected true; got %v", ok)
	}

	if _, err := Change(oldPassword, "wrongpassword", newPassword, newPassword, false); err != ErrIncorrectPassword {
		t.Errorf("expected ErrIncorrectPassword; got %v", err)
	}

	if _, err := Change(oldPassword, oldPassword, newPassword, "wrongpassword", false); err != ErrConfirmPasswordNotMatch {
		t.Errorf("expected ErrConfirmPasswordNotMatch; got %v", err)
	}

	if _, err := Change(oldPassword, oldPassword, oldPassword, oldPassword, false); err != ErrSamePassword {
		t.Errorf("expected ErrSamePassword; got %v", err)
	}

	if _, err := Change(oldPassword, oldPassword, "", "", false); err != ErrBlankPassword {
		t.Errorf("expected ErrBlankPassword; got %v", err)
	}

	if _, err := Change(oldPassword, oldPassword, oldPassword, newPassword, false); err != ErrConfirmPasswordNotMatch {
		t.Errorf("expected ErrConfirmPasswordNotMatch; got %v", err)
	}
}
