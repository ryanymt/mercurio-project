package viewer_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/viewer"
)

const (
	email     = "operator@example.com"
	signature = "SIGNATURE-MUST-NEVER-BE-SHOWN"
	phone     = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) Mobile Safari"
)

// assertion builds an IAP-shaped assertion from its parts; nothing here signs it.
func assertion(t *testing.T, header, claims any, sig string) string {
	t.Helper()
	part := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return part(header) + "." + part(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte(sig))
}

func iapHeader() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "JWT", "kid": "key-id-1"}
}

func iapClaims() map[string]any {
	return map[string]any{
		"email": email, "sub": "accounts.google.com:1234567890", "hd": "example.com",
		"iss": "https://cloud.google.com/iap", "aud": "/projects/123456789012/locations/us-central1/services/viewer",
		"iat": 1790000000, "exp": 1790000600,
	}
}

// serve sends one request to the viewer and returns the response and what it logged.
func serve(t *testing.T, r *http.Request) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var logs bytes.Buffer
	w := httptest.NewRecorder()
	viewer.WhoAmI(slog.New(slog.NewJSONHandler(&logs, nil))).ServeHTTP(w, r)
	return w, logs.String()
}

func whoami(t *testing.T, raw string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Goog-Iap-Jwt-Assertion", raw)
	r.Header.Set("User-Agent", phone)
	r.Header.Set("X-Goog-Authenticated-User-Email", "accounts.google.com:"+email)
	r.Header.Set("X-Goog-Authenticated-User-Id", "accounts.google.com:1234567890")
	return r
}

// The page shows the assertion's header and claims, the user agent, IAP's identity headers, and the
// names of every request header: what T3's verifier and fixtures are built from (P06 D18).
func TestShowsWhoIAPSaysYouAre(t *testing.T) {
	w, _ := serve(t, whoami(t, assertion(t, iapHeader(), iapClaims(), signature)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		email, "ES256", "key-id-1", "accounts.google.com:1234567890", "https://cloud.google.com/iap",
		"/projects/123456789012/locations/us-central1/services/viewer", "example.com",
		"1790000600", "2026-09-21T", // exp as given, and as a time
		"iPhone", "accounts.google.com:" + email, "X-Goog-Authenticated-User-Id",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
}

// The signature, the raw assertion and every other header's value are never shown or logged: the
// page is for reading claims, and a request's credentials stay out of the page and the log.
func TestNeverShowsTheSignatureOrCredentials(t *testing.T) {
	raw := assertion(t, iapHeader(), iapClaims(), signature)
	r := whoami(t, raw)
	r.Header.Set("Authorization", "Bearer authorization-value")
	r.Header.Set("X-Serverless-Authorization", "Bearer serverless-value")
	r.Header.Set("Cookie", "GCP_IAP_UID=cookie-value")
	w, logs := serve(t, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	sig := raw[strings.LastIndex(raw, ".")+1:]
	for _, secret := range []string{signature, sig, raw, "authorization-value", "serverless-value", "cookie-value"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("the page shows %q", secret)
		}
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
	for _, name := range []string{"Authorization", "X-Serverless-Authorization", "Cookie"} {
		if !strings.Contains(w.Body.String(), name) {
			t.Errorf("the page does not name the header %s", name)
		}
	}
}

// What the page shows is escaped: a claim or header holding markup renders inert.
func TestEscapesWhatItShows(t *testing.T) {
	claims := iapClaims()
	claims["email"] = `<script>alert(1)</script>@example.com`
	header := iapHeader()
	header["kid"] = `"><img src=x onerror=alert(2)>`
	r := whoami(t, assertion(t, header, claims, signature))
	r.Header.Set("User-Agent", `<b>agent</b>`)
	w, _ := serve(t, r)
	body := w.Body.String()
	for _, raw := range []string{"<script>alert(1)", "<img src=x", "<b>agent"} {
		if strings.Contains(body, raw) {
			t.Errorf("the page renders %q unescaped", raw)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the escaped email is missing")
	}
}

// Every response carries a CSP allowing no script, and is neither sniffed, cached nor referred.
func TestSecurityHeaders(t *testing.T) {
	for name, r := range map[string]*http.Request{
		"page":    whoami(t, assertion(t, iapHeader(), iapClaims(), signature)),
		"refusal": httptest.NewRequest(http.MethodGet, "/", nil),
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := serve(t, r)
			h := w.Header()
			if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
				t.Errorf("CSP %q", csp)
			}
			for k, v := range map[string]string{
				"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
			} {
				if h.Get(k) != v {
					t.Errorf("%s is %q, want %q", k, h.Get(k), v)
				}
			}
		})
	}
}

// Without an assertion the page refuses (401); a malformed one is refused (400) without echoing it;
// only GET and HEAD of / are served.
func TestRefusals(t *testing.T) {
	w, _ := serve(t, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "IAP") {
		t.Fatalf("no assertion: status %d, %s", w.Code, w.Body)
	}

	good := assertion(t, iapHeader(), iapClaims(), signature)
	parts := strings.Split(good, ".")
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, raw := range map[string]string{
		"two parts":          parts[0] + "." + parts[1],
		"four parts":         good + ".extra",
		"header not base64":  "!!!." + parts[1] + "." + parts[2],
		"claims not base64":  parts[0] + ".%%%." + parts[2],
		"header not JSON":    enc("not json") + "." + parts[1] + "." + parts[2],
		"claims not JSON":    parts[0] + "." + enc("not json") + "." + parts[2],
		"claims not object":  parts[0] + "." + enc(`["a"]`) + "." + parts[2],
		"claims null":        parts[0] + "." + enc("null") + "." + parts[2],
		"header null":        enc("null") + "." + parts[1] + "." + parts[2],
		"too long":           parts[0] + "." + enc(`{"pad":"`+strings.Repeat("x", 9000)+`"}`) + "." + parts[2],
		"empty signature":    parts[0] + "." + parts[1] + ".",
		"padded base64 part": parts[0] + "=." + parts[1] + "." + parts[2],
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := serve(t, whoami(t, raw))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), parts[2]) || strings.Contains(w.Body.String(), raw) {
				t.Fatal("the refusal echoes the assertion")
			}
		})
	}

	post := whoami(t, good)
	post.Method = http.MethodPost
	if w, _ := serve(t, post); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: status %d, Allow %q", w.Code, w.Header().Get("Allow"))
	}
	head := whoami(t, good)
	head.Method = http.MethodHead
	if w, _ := serve(t, head); w.Code != http.StatusOK {
		t.Fatalf("HEAD: status %d", w.Code)
	}
	other := whoami(t, good)
	other.URL.Path = "/other"
	if w, _ := serve(t, other); w.Code != http.StatusNotFound {
		t.Fatalf("/other: status %d", w.Code)
	}
}

// Each page served logs the claims, the key id, the user agent and the header names, so a sign-in
// can be read back from the request log as evidence.
func TestLogsWhatItShows(t *testing.T) {
	_, logs := serve(t, whoami(t, assertion(t, iapHeader(), iapClaims(), signature)))
	var line struct {
		Msg         string         `json:"msg"`
		Header      map[string]any `json:"assertion_header"`
		Claims      map[string]any `json:"claims"`
		UserAgent   string         `json:"user_agent"`
		HeaderNames []string       `json:"header_names"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs)), &line); err != nil {
		t.Fatalf("one JSON log line expected: %v\n%s", err, logs)
	}
	if line.Claims["email"] != email || line.Header["kid"] != "key-id-1" || line.UserAgent != phone {
		t.Fatalf("log line %+v", line)
	}
	if !strings.Contains(strings.Join(line.HeaderNames, " "), "X-Goog-Authenticated-User-Email") {
		t.Fatalf("header names %v", line.HeaderNames)
	}
}
