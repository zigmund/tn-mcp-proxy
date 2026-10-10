package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-version"}, &out, &errOut); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Errorf("version output = %q, want %q", got, version)
	}
}

func TestRunNotImplemented(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"-config", "x.yaml"}, &out, &errOut)
	if !errors.Is(err, errNotImplemented) {
		t.Fatalf("err = %v, want errNotImplemented", err)
	}
}

func TestRunBadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-nope"}, &out, &errOut); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
