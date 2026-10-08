package capture

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
)

// Scrubbing (P06 D10): every line is scrubbed before it leaves the runner, by the exact values the
// runner knows to be secret and by patterns for the common secret shapes. Each match becomes
// [redacted:<kind>]. Scrubbing reduces what is stored; the bucket's privacy and IAP are the
// protection, and a key of a shape no rule knows passes (P06 Risks).
//
// The patterns follow gitleaks' rules of the same ids (https://github.com/gitleaks/gitleaks, MIT;
// GITLEAKS_LICENSE beside this file), with RE2's syntax and with the secret, not its delimiters,
// as the part replaced. Ours: private-key-unterminated, google-oauth-token, authorization-header,
// url-credentials, url-encoded-credentials and credential-assignment, the last a narrower form of
// gitleaks' generic-api-key that spares counts such as Claude Code's input_tokens.

// rule is one secret shape; the part replaced is the group named s, so delimiters and the names
// around a secret stay.
type rule struct {
	kind string
	re   *regexp.Regexp
}

// end is gitleaks' delimiter after a token: a quote, space or semicolon, an escaped newline in a
// JSON string, or the end of the text.
const end = `(?:[\x60'"\s;]|\\[nr]|$)`

// rules run in this order, after the known values: the most specific first.
var rules = []rule{
	{"private-key", regexp.MustCompile(`(?i)(?P<s>-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?KEY(?: BLOCK)?-----)`)},
	// A key cut off before its end, as a truncated output leaves it: the header and every key
	// character after it, escaped newlines included.
	{"private-key-unterminated", regexp.MustCompile(`(?i)(?P<s>-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/=\s]|\\[nr])*)`)},
	{"github-pat", regexp.MustCompile(`(?P<s>ghp_[0-9a-zA-Z]{36})`)},
	{"github-oauth", regexp.MustCompile(`(?P<s>gho_[0-9a-zA-Z]{36})`)},
	{"github-app-token", regexp.MustCompile(`(?P<s>(?:ghu|ghs)_[0-9a-zA-Z]{36})`)},
	{"github-refresh-token", regexp.MustCompile(`(?P<s>ghr_[0-9a-zA-Z]{36})`)},
	{"github-fine-grained-pat", regexp.MustCompile(`(?P<s>github_pat_\w{82})`)},
	{"gcp-api-key", regexp.MustCompile(`\b(?P<s>AIza[\w-]{35})` + end)},
	{"google-oauth-token", regexp.MustCompile(`\b(?P<s>ya29\.[0-9A-Za-z_-]{20,})`)},
	// gitleaks' class also takes a backslash, which would swallow a JSON line's escape; this does not.
	{"jwt", regexp.MustCompile(`\b(?P<s>ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_-]{17,}\.(?:[a-zA-Z0-9/_-]{10,}={0,2})?)` + end)},
	{"anthropic-api-key", regexp.MustCompile(`\b(?P<s>sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{20,})`)},
	{"openai-api-key", regexp.MustCompile(`\b(?P<s>sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})` + end)},
	{"aws-access-token", regexp.MustCompile(`\b(?P<s>(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`)},
	{"slack-bot-token", regexp.MustCompile(`(?P<s>xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)`)},
	{"slack-user-token", regexp.MustCompile(`(?P<s>xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34})`)},
	{"stripe-access-token", regexp.MustCompile(`\b(?P<s>(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})` + end)},
	{"gitlab-pat", regexp.MustCompile(`(?P<s>glpat-[\w-]{20})`)},
	{"npm-access-token", regexp.MustCompile(`(?i)\b(?P<s>npm_[a-z0-9]{36})` + end)},
	// A credential header's value, in a request, a command line or an escaped JSON string.
	{"authorization-header", regexp.MustCompile(`(?i)\b(?:proxy-authorization|x-serverless-authorization|authorization|` +
		`x-foreman-claim-token|x-foreman-iap-assertion|x-goog-iap-jwt-assertion)(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?` +
		`(?:(?:bearer|basic|token)\s+)?(?P<s>[^\s"'\\,;]+)`)},
	{"url-credentials", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://(?P<s>[^\s/:@"'\\]+:[^\s/@"'\\]+)@`)},
	{"url-encoded-credentials", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*%3A%2F%2F(?P<s>[^\s/"'\\@]*?%3A[^\s/"'\\@]*?)%40`)},
	// name=value, name: value and "name": "value" for names that hold credentials. The name must end
	// at a word boundary, so input_tokens and max_tokens are not "token".
	{"credential-assignment", regexp.MustCompile(`(?i)\b(?:[a-z0-9]+[_.-])*(?:password|passwd|passphrase|secret|client[_-]?secret|` +
		`api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|` +
		`id[_-]?token|token)\b(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?(?P<s>[^\s"'\\,;&\[\]{}]{4,})`)},
}

// minKnown is the shortest known value taken: a shorter one cannot be told from ordinary text.
const minKnown = 8

// Scrubber redacts secrets from text.
type Scrubber struct {
	known []string // the known values and their base64 forms, longest first
}

// NewScrubber redacts the given values, wherever they appear, besides the patterns. A value
// shorter than minKnown is ignored.
func NewScrubber(known ...string) *Scrubber {
	s := &Scrubber{}
	seen := map[string]bool{}
	add := func(f string) {
		if len(f) >= minKnown && !seen[f] {
			seen[f] = true
			s.known = append(s.known, f)
		}
	}
	for _, v := range known {
		if len(v) < minKnown {
			continue
		}
		add(v)
		for _, f := range base64Forms(v) {
			add(f)
		}
	}
	sort.Slice(s.known, func(i, j int) bool { return len(s.known[i]) > len(s.known[j]) })
	return s
}

// base64Forms are the runs of standard and URL-safe base64 characters that encode only v's own
// bytes, at each of the three offsets v can start at in an encoded blob: whatever precedes or
// follows v, and whatever padding, its encoding holds one of these (P05's cloudruntest.Leaks).
func base64Forms(v string) []string {
	var forms []string
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for k := 0; k < 3; k++ {
			blob := enc.EncodeToString(append(make([]byte, k), v...))
			first, last := (k+2)/3, (k+len(v))/3
			if last > first {
				forms = append(forms, blob[4*first:4*last])
			}
		}
	}
	return forms
}

// Scrub returns text with every known value and every rule's match replaced.
func (s *Scrubber) Scrub(text string) string {
	for _, f := range s.known {
		text = strings.ReplaceAll(text, f, "[redacted:known-value]")
	}
	for _, r := range rules {
		text = r.redact(text)
	}
	return text
}

func (r rule) redact(text string) string {
	matches := r.re.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return text
	}
	i := r.re.SubexpIndex("s")
	var b strings.Builder
	last := 0
	for _, m := range matches {
		start, stop := m[2*i], m[2*i+1]
		if start < 0 {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString("[redacted:" + r.kind + "]")
		last = stop
	}
	b.WriteString(text[last:])
	return b.String()
}
