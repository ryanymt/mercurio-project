package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultMetadataHost  = "metadata.google.internal"
	defaultSecretManager = "https://secretmanager.googleapis.com"
	callTimeout          = 30 * time.Second
)

// google is the runner's view of Google: the metadata server, which speaks for the job's account,
// and Secret Manager.
type google struct {
	metadata      string
	secretManager string
	http          *http.Client
}

func newGoogle(metadataHost, secretManager string) *google {
	if metadataHost == "" {
		metadataHost = defaultMetadataHost
	}
	if secretManager == "" {
		secretManager = defaultSecretManager
	}
	return &google{metadata: "http://" + metadataHost + "/computeMetadata/v1/instance/service-accounts/default/",
		secretManager: strings.TrimSuffix(secretManager, "/"), http: &http.Client{Timeout: callTimeout}}
}

// fromMetadata asks the metadata server for path, returning the answer's body.
func (g *google) fromMetadata(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", g.metadata+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the metadata server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the metadata server: %s: status %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// idToken is an ID token for audience. format=full puts the account's email in it, which the
// callback API's verifier requires (R3).
func (g *google) idToken(ctx context.Context, audience string) (string, error) {
	b, err := g.fromMetadata(ctx, "identity?"+url.Values{"audience": {audience}, "format": {"full"}}.Encode())
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("the metadata server answered with no ID token")
	}
	return tok, nil
}

// accessToken is the job's OAuth access token, for Secret Manager and Cloud Storage.
func (g *google) accessToken(ctx context.Context) (string, error) {
	b, err := g.fromMetadata(ctx, "token")
	if err != nil {
		return "", err
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("the metadata server answered with no access token")
	}
	return t.AccessToken, nil
}

// secret reads one version of a secret (projects/P/secrets/S/versions/N) as the job's account. A
// numbered version reads consistently, where latest would not (D17).
func (g *google) secret(ctx context.Context, version string) ([]byte, error) {
	token, err := g.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", g.secretManager+"/v1/"+version+":access", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("access %s: %w", version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access %s: status %d", version, resp.StatusCode)
	}
	var got struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&got); err != nil {
		return nil, fmt.Errorf("access %s: an unreadable answer", version)
	}
	data, err := base64.StdEncoding.DecodeString(got.Payload.Data)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("access %s: no payload", version)
	}
	return data, nil
}
