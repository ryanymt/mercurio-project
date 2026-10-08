// Package viewer is foreman's private web viewer, reached only through IAP (P06 Approach 4).
//
// It shows tickets, their events and attempts, each attempt's transcript as a harness-neutral
// timeline (D22), the diff base...head and the stored verdict, and relays a person's acts to the
// callback API with their IAP assertion, which the API verifies itself (D4). It reads the database
// as the read-only `viewer` user (D7) and writes nothing. Every request's assertion is verified
// here too, and every page is server-rendered, escaped, under a CSP with no script (D17).
//
// WhoAmI is the IAP spike's page (D18, T2): what IAP's assertion says about the person reaching it,
// decoded, never its signature.
package viewer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// assertionHeader carries IAP's signed assertion, an ES256 JWT naming the person.
const assertionHeader = "X-Goog-Iap-Jwt-Assertion"

// maxAssertion bounds what the page decodes; IAP's assertions are about a kilobyte.
const maxAssertion = 8 << 10

// shownHeaders are the request headers whose values the page shows and logs. Every other header is
// shown by name only, so no credential a request carries reaches the page or the log.
var shownHeaders = []string{"User-Agent", "X-Goog-Authenticated-User-Email", "X-Goog-Authenticated-User-Id"}

// timeClaims are the claims holding Unix times, also shown as UTC times.
var timeClaims = map[string]bool{"iat": true, "exp": true, "nbf": true}

// WhoAmI serves the spike's page, for GET and HEAD, at / of its own handler or /whoami of the
// viewer's.
func WhoAmI(log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w.Header())
		if r.URL.Path != "/" && r.URL.Path != "/whoami" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw := r.Header.Get(assertionHeader)
		if raw == "" {
			http.Error(w, "no IAP assertion: this service is reached only through IAP", http.StatusUnauthorized)
			return
		}
		a, err := decode(raw)
		if err != nil {
			http.Error(w, "the IAP assertion could not be decoded", http.StatusBadRequest)
			return
		}

		p := page{Header: rows(a.header), Claims: rows(a.claims), Names: headerNames(r.Header)}
		if e, ok := a.claims["email"].(string); ok {
			p.Email = e
		}
		for _, h := range shownHeaders {
			if v := r.Header.Get(h); v != "" {
				p.Shown = append(p.Shown, row{Name: h, Value: v})
			}
		}
		log.Info("viewer: who am i", "assertion_header", a.header, "claims", a.claims,
			"user_agent", r.UserAgent(), "header_names", p.Names)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplate.Execute(w, p); err != nil {
			log.Error("viewer: render the page", "error", err)
		}
	})
}

// secure sets the headers every response carries: a CSP that allows no script and no framing, its
// own stylesheet and forms posted to itself alone, and no sniffing, caching or referrer.
func secure(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
}

// assertion is a decoded assertion's header and claims; its signature is never kept.
type assertion struct {
	header, claims map[string]any
}

// decode reads a JWT's header and claims without verifying it. It refuses anything that is not
// three non-empty dot-separated parts whose first two are unpadded base64url JSON objects.
func decode(raw string) (assertion, error) {
	malformed := errors.New("malformed assertion")
	if len(raw) > maxAssertion {
		return assertion{}, malformed
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return assertion{}, malformed
	}
	var a assertion
	for i, dst := range []*map[string]any{&a.header, &a.claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return assertion{}, malformed
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(dst); err != nil || *dst == nil {
			return assertion{}, malformed
		}
	}
	return a, nil
}

type row struct{ Name, Value, Note string }

type page struct {
	Email                 string
	Header, Claims, Shown []row
	Names                 []string
}

// rows lists an object's fields by name, strings as they are and anything else as JSON, with Unix
// times also shown as UTC times.
func rows(m map[string]any) []row {
	var out []row
	for k, v := range m {
		r := row{Name: k}
		if s, ok := v.(string); ok {
			r.Value = s
		} else {
			b, _ := json.Marshal(v)
			r.Value = string(b)
		}
		if n, ok := v.(json.Number); ok && timeClaims[k] {
			if secs, err := strconv.ParseInt(n.String(), 10, 64); err == nil {
				r.Note = time.Unix(secs, 0).UTC().Format(time.RFC3339)
			}
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b row) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// headerNames lists every request header's name, sorted.
func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

var pageTemplate = template.Must(template.New("whoami").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Who IAP says you are</title>
</head>
<body>
<h1>Who IAP says you are</h1>
<p><strong>{{if .Email}}{{.Email}}{{else}}(no email claim){{end}}</strong></p>
<p>The assertion IAP sent with this request, decoded and not verified. Its signature is never shown.</p>
<h2>The assertion's header</h2>
<table>
{{range .Header}}<tr><th>{{.Name}}</th><td>{{.Value}}</td></tr>
{{end}}</table>
<h2>Its claims</h2>
<table>
{{range .Claims}}<tr><th>{{.Name}}</th><td>{{.Value}}</td><td>{{.Note}}</td></tr>
{{end}}</table>
<h2>The request</h2>
<table>
{{range .Shown}}<tr><th>{{.Name}}</th><td>{{.Value}}</td></tr>
{{end}}</table>
<p>Every header received, by name: {{range $i, $n := .Names}}{{if $i}}, {{end}}{{$n}}{{end}}</p>
</body>
</html>
`))
