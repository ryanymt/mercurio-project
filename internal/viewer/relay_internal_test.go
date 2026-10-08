package viewer

import (
	"context"
	"testing"
	"time"
)

// The relay waits longer than a callback API cold start: 69 s was seen in GCP, longer than the
// first 30 s (the validation round).
func TestTheRelayWaitsOutAColdStart(t *testing.T) {
	r, err := NewHTTPRelay("https://callback-api.example.test", func(context.Context, string) (string, error) { return "", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.client.Timeout != 90*time.Second {
		t.Fatalf("the relay waits %v, want 90s", r.client.Timeout)
	}
}
