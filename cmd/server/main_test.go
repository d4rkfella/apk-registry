package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
)

func TestDependencyLogsUseJSONLogger(t *testing.T) {
	previousLogger := slog.Default()
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	var output bytes.Buffer
	newJSONLogger(&output)
	log.Print("standard library log")
	clog.FromContext(context.Background()).Infof("dependency log")

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2: %q", len(lines), output.String())
	}
	for i, wantMessage := range []string{"standard library log", "dependency log"} {
		var record struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &record); err != nil {
			t.Fatalf("log line %d is not JSON: %v", i+1, err)
		}
		if record.Level != "INFO" || record.Msg != wantMessage {
			t.Fatalf("log line %d = %+v, want INFO %q", i+1, record, wantMessage)
		}
	}
}
