package runner

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ryanymt/mercurio-project/internal/capture"
)

// probe records in the transcript what the runner's account may do in the artifacts bucket, as GCP
// enforces it (P06 Approach 7; red team R7): creating under its own project's prefix, which its
// transcript's first chunk does, is allowed; creating under another project's prefix, reading an
// object and listing are denied. A result other than expected is recorded, not acted on: the
// transcript is the evidence, read in GCP.
func probe(ctx context.Context, c *capture.Capture, g *google, storage, bucket, project, run string) {
	record := func(check string, status int, err error) {
		result := "error"
		switch {
		case err == nil && status/100 == 2:
			result = "allowed"
		case err == nil && (status == http.StatusUnauthorized || status == http.StatusForbidden):
			result = "denied"
		}
		line := map[string]any{"step": "probe", "check": check, "result": result, "status": status}
		if err != nil {
			line["error"] = err.Error()
		}
		c.Event(capture.Transcript, line)
	}

	// Creating under its own prefix: the transcript's first chunk.
	if err := c.Flush(ctx); err != nil {
		record("create under its own prefix", 0, err)
	} else {
		record("create under its own prefix", http.StatusOK, nil)
	}
	other := "foreman"
	if project == "foreman" {
		other = "sandbox"
	}
	q := url.Values{"uploadType": {"media"}, "name": {other + "/probe/" + run}, "ifGenerationMatch": {"0"}}
	status, err := storageCall(ctx, g, http.MethodPost, storage+"/upload/storage/v1/b/"+url.PathEscape(bucket)+"/o?"+q.Encode(), "probe\n")
	record("create under another project's prefix", status, err)
	first := c.Prefix(capture.Transcript) + "/000001.jsonl"
	status, err = storageCall(ctx, g, http.MethodGet, storage+"/storage/v1/b/"+url.PathEscape(bucket)+"/o/"+url.PathEscape(first)+"?alt=media", "")
	record("get an object", status, err)
	q = url.Values{"prefix": {c.Prefix(capture.Transcript)}}
	status, err = storageCall(ctx, g, http.MethodGet, storage+"/storage/v1/b/"+url.PathEscape(bucket)+"/o?"+q.Encode(), "")
	record("list objects", status, err)
}

// storageCall makes one Cloud Storage request as the job's account and returns its status.
func storageCall(ctx context.Context, g *google, method, u, body string) (int, error) {
	token, err := g.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("storage: %w", err)
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// canary is a token-shaped string made at run time, in a GitHub App token's shape: the transcript
// must hold it only as redacted, which proves in GCP that the scrubber runs where the transcript is
// written (red team R7). It is never logged.
func canary() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 36)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "ghs_" + string(b)
}
