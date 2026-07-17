package ble

import (
	"errors"
	"testing"
)

func TestGetPasskeyExplicit(t *testing.T) {
	a := &AuthData{Passkey: 123456}
	got, err := a.GetPasskey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 123456 {
		t.Fatalf("got %d, want 123456", got)
	}
}

func TestGetPasskeyExplicitWinsOverFn(t *testing.T) {
	calls := 0
	a := &AuthData{
		Passkey:   123456,
		PasskeyFn: func() (int, error) { calls++; return 999999, nil },
	}
	got, err := a.GetPasskey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 123456 {
		t.Fatalf("got %d, want 123456", got)
	}
	if calls != 0 {
		t.Fatalf("PasskeyFn called %d times, want 0", calls)
	}
}

func TestGetPasskeyFnCalledOnce(t *testing.T) {
	calls := 0
	a := &AuthData{PasskeyFn: func() (int, error) { calls++; return 42, nil }}
	for i := 0; i < 3; i++ {
		got, err := a.GetPasskey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	}
	if calls != 1 {
		t.Fatalf("PasskeyFn called %d times, want 1", calls)
	}
}

// A passkey of 0 (i.e. "000000") is valid and must be cached like any other
// value instead of causing repeated prompts.
func TestGetPasskeyFnZeroCached(t *testing.T) {
	calls := 0
	a := &AuthData{PasskeyFn: func() (int, error) { calls++; return 0, nil }}
	for i := 0; i < 3; i++ {
		got, err := a.GetPasskey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	}
	if calls != 1 {
		t.Fatalf("PasskeyFn called %d times, want 1", calls)
	}
}

func TestGetPasskeyFnErrorCached(t *testing.T) {
	calls := 0
	wantErr := errors.New("user gave up")
	a := &AuthData{PasskeyFn: func() (int, error) { calls++; return 0, wantErr }}
	for i := 0; i < 3; i++ {
		_, err := a.GetPasskey()
		if !errors.Is(err, wantErr) {
			t.Fatalf("got error %v, want %v", err, wantErr)
		}
	}
	if calls != 1 {
		t.Fatalf("PasskeyFn called %d times, want 1", calls)
	}
}

func TestGetPasskeyNoSource(t *testing.T) {
	a := &AuthData{}
	got, err := a.GetPasskey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestHasPasskeySource(t *testing.T) {
	cases := []struct {
		name string
		a    AuthData
		want bool
	}{
		{"empty", AuthData{}, false},
		{"explicit", AuthData{Passkey: 1}, true},
		{"fn", AuthData{PasskeyFn: func() (int, error) { return 0, nil }}, true},
	}
	for _, c := range cases {
		if got := c.a.HasPasskeySource(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
