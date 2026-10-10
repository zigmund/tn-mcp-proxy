package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestNewJSONAndLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.Log{Level: "warn", Format: "json"}, &buf)
	log.Info("hidden")
	log.Warn("shown", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not a single JSON record: %q: %v", buf.String(), err)
	}
	if rec["msg"] != "shown" || rec["k"] != "v" || rec["level"] != "WARN" {
		t.Fatalf("unexpected record: %v", rec)
	}
}

func TestNewText(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.Log{Level: "debug", Format: "text"}, &buf)
	log.Debug("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "msg=hello") || !strings.Contains(out, "k=v") {
		t.Fatalf("unexpected text output: %q", out)
	}
}

func TestNewUnknownLevelIsInfo(t *testing.T) {
	var buf bytes.Buffer
	log := New(config.Log{Level: "bogus", Format: "json"}, &buf)
	log.Debug("hidden")
	if buf.Len() != 0 {
		t.Fatalf("debug logged at info level: %q", buf.String())
	}
	log.Info("shown")
	if buf.Len() == 0 {
		t.Fatal("info not logged")
	}
}
