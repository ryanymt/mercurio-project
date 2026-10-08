package capture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
)

// Every secret below is assembled at run time, so no realistic secret shape sits in the source.

func rep(s string, n int) string { return strings.Repeat(s, n) }

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// sample is a text holding a secret, and the secret itself, which must be gone after scrubbing.
type sample struct{ text, secret string }

func in(format, secret string) sample { return sample{fmt.Sprintf(format, secret), secret} }

var keyBody = rep("MIIEvQIBADANBgkq", 6)

// ruleCases holds, for every rule, texts it must redact and near misses it must leave alone
// (consult 1: a sample and a near miss per rule).
var ruleCases = map[string]struct {
	samples    []sample
	nearMisses []string
}{
	"private-key": {
		samples: []sample{
			in("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----", keyBody),
			// A service-account key file's escaped newlines, and the same file inside a JSON line.
			in(`{"private_key": "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n"}`, keyBody),
			in(`{"text":"{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n%s\\n-----END PRIVATE KEY-----\\n\"}"}`, keyBody),
			in("-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----", keyBody),
			in("-----BEGIN PGP PRIVATE KEY BLOCK-----\n%s\n-----END PGP PRIVATE KEY BLOCK-----", keyBody),
		},
		nearMisses: []string{
			"-----BEGIN PUBLIC KEY-----\n" + keyBody + "\n-----END PUBLIC KEY-----",
			"-----BEGIN CERTIFICATE-----\n" + keyBody + "\n-----END CERTIFICATE-----",
			"no private key is printed here",
		},
	},
	"private-key-unterminated": {
		samples: []sample{
			in("-----BEGIN PRIVATE KEY-----\n%s", keyBody),
			in(`"output":"-----BEGIN EC PRIVATE KEY-----\n%s... (truncated)"`, keyBody),
		},
		nearMisses: []string{"-----BEGIN CERTIFICATE-----\n" + keyBody},
	},
	"github-pat": {
		samples:    []sample{in("token %s here", "ghp_"+rep("aB3d", 9)), in(`{"t":"%s"}`, "ghp_"+rep("Zz09", 9))},
		nearMisses: []string{"ghp_" + rep("a", 35), "ghp_ is GitHub's classic prefix"},
	},
	"github-oauth": {
		samples:    []sample{in("%s", "gho_"+rep("aB3d", 9))},
		nearMisses: []string{"gho_" + rep("a", 20)},
	},
	"github-app-token": {
		samples:    []sample{in("x %s y", "ghs_"+rep("aB3d", 9)), in("%s", "ghu_"+rep("Qq77", 9))},
		nearMisses: []string{"ghs_" + rep("b", 30), "ghs_ and ghu_ tokens"},
	},
	"github-refresh-token": {
		samples:    []sample{in("%s", "ghr_"+rep("aB3d", 9))},
		nearMisses: []string{"ghr_" + rep("c", 12)},
	},
	"github-fine-grained-pat": {
		samples:    []sample{in("GH=%s", "github_pat_"+rep("11ABCDEFG0", 8)+"ab")},
		nearMisses: []string{"github_pat_" + rep("1", 40)},
	},
	"gcp-api-key": {
		samples:    []sample{in(`"%s"`, "AIza"+rep("SyA1b2C3d4", 3)+"e5F6g"), in("key %s\n", "AIza"+rep("q", 35))},
		nearMisses: []string{"AIza" + rep("q", 36) + "x", "AIza alone"},
	},
	"google-oauth-token": {
		samples:    []sample{in("Bearer-less %s", "ya29."+rep("a0AfB_byC1", 4))},
		nearMisses: []string{"ya29 without its dot", "ya29.short"},
	},
	"jwt": {
		samples: []sample{in("%s", b64url(`{"alg":"ES256","typ":"JWT","kid":"1"}`)+"."+
			b64url(`{"email":"a@example.com","aud":"x"}`)+"."+rep("sigSIG012_", 3))},
		nearMisses: []string{b64url(`{"a":1}`) + "." + b64url(`{"b":2}`)},
	},
	"anthropic-api-key": {
		samples:    []sample{in("%s", "sk-ant-api03-"+rep("Ab1_", 23)+"AA"), in("k=%s;", "sk-ant-admin01-"+rep("Zz9-", 10))},
		nearMisses: []string{"task-ant-api03-" + rep("Ab1_", 10), "sk-ant-short"},
	},
	"openai-api-key": {
		samples: []sample{in("%s", "sk-proj-"+rep("Ab1_", 18)+"Ab"+"T3BlbkFJ"+rep("Cd2-", 18)+"Cd"),
			in("%s ", "sk-"+rep("aB3dE", 4)+"T3BlbkFJ"+rep("fG4hI", 4))},
		nearMisses: []string{"sk-proj-short", "sk-" + rep("a", 20)},
	},
	"aws-access-token": {
		samples:    []sample{in("id=%s", "AKIA"+rep("ABCD2345", 2)), in("%s", "ASIA"+rep("WXYZ7654", 2))},
		nearMisses: []string{"AKIA" + rep("abcd2345", 2), "AKIA" + rep("ABCD2345", 2) + "Q"},
	},
	"slack-bot-token": {
		samples:    []sample{in("%s", "xoxb-1234567890-1234567890123-"+rep("aB3", 8))},
		nearMisses: []string{"xoxb-12-34"},
	},
	"slack-user-token": {
		samples:    []sample{in("%s", "xoxp-1234567890-1234567890-1234567890-"+rep("aBcD1234", 4))},
		nearMisses: []string{"xoxp-1-2-3-4"},
	},
	"stripe-access-token": {
		samples:    []sample{in("%s", "sk_"+"live_"+rep("aB3dE", 5)), in("%s;", "rk_"+"test_"+rep("Zz9", 6))},
		nearMisses: []string{"sk_" + "live_" + "abc", "desk_" + "live_" + rep("x", 12)},
	},
	"gitlab-pat": {
		samples:    []sample{in("%s", "glpat-"+rep("aB3d_", 4))},
		nearMisses: []string{"glpat-short"},
	},
	"npm-access-token": {
		samples:    []sample{in("//registry.npmjs.org/:_authToken=%s", "npm_"+rep("aB3d", 9))},
		nearMisses: []string{"npm_" + rep("aB3d", 9) + "x", "npm_short"},
	},
	"authorization-header": {
		samples: []sample{
			in("Authorization: Bearer %s", "opaque-token-value-123"),
			in(`"authorization":"Basic %s"`, "dXNlcjpwYXNzd29yZA"),
			in("-H 'authorization: token %s'", "another-opaque-value"),
			in(`{"cmd":"curl -H \"Authorization: Bearer %s\""}`, "escaped-in-a-line-42"),
			in("X-Foreman-Claim-Token: %s", "claim-token-1234"),
			in("X-Foreman-IAP-Assertion: %s", "assertion-value-99"),
			in("x-serverless-authorization: Bearer %s", "iap-to-cloud-run"),
		},
		nearMisses: []string{"Authorization required", "the authorization header", "authorization: "},
	},
	"url-credentials": {
		samples: []sample{
			in("https://%s@github.com/ryanymt/sandbox.git", "x-access-token:abc123SECRETvalue"),
			in("postgres://%s@10.0.0.3:5432/foreman", "app:p4ssw0rd!"),
		},
		nearMisses: []string{"https://github.com/foo@bar", "mailto:someone@example.com", "git@github.com:org/repo.git"},
	},
	"url-encoded-credentials": {
		samples:    []sample{in("redirect=https%%3A%%2F%%2F%s%%40github.com", "x-access-token%3AsecretValue77")},
		nearMisses: []string{"https%3A%2F%2Fexample.com%2Fpath"},
	},
	"credential-assignment": {
		samples: []sample{
			in("password=%s", "hunter2hunter2"),
			in("DB_PASSWORD: %s", "correct-horse"),
			in(`{"api_key": "%s"}`, "zxcvbnm123"),
			in(`{"text":"\"client_secret\":\"%s\""}`, "s3cr3t-value"),
			in("export GITHUB_TOKEN=%s", "plain-value-777"),
		},
		nearMisses: []string{
			`"usage":{"input_tokens": 1234567, "output_tokens":42, "cache_read_input_tokens":99999}`,
			"password_policy: strict", "tokenizer=bpe", "the password is wrong", "max_tokens=4096",
		},
	},
}

// Every rule redacts each of its samples, keeping what surrounds the secret, and leaves its near
// misses as they are; every rule has a case and every case a rule.
func TestEveryRuleRedactsItsSamplesAndSparesItsNearMisses(t *testing.T) {
	s := NewScrubber()
	seen := map[string]bool{}
	for _, r := range rules {
		seen[r.kind] = true
		c, ok := ruleCases[r.kind]
		if !ok || len(c.samples) == 0 || len(c.nearMisses) == 0 {
			t.Errorf("rule %s has no sample or no near miss", r.kind)
			continue
		}
		for _, smp := range c.samples {
			out := s.Scrub(smp.text)
			if strings.Contains(out, smp.secret) || !strings.Contains(out, "[redacted:"+r.kind+"]") {
				t.Errorf("%s: %q scrubbed to %q", r.kind, smp.text, out)
			}
			if s.Scrub(out) != out {
				t.Errorf("%s: scrubbing again changed %q", r.kind, out)
			}
		}
		for _, near := range c.nearMisses {
			if out := s.Scrub(near); out != near {
				t.Errorf("%s: near miss %q scrubbed to %q", r.kind, near, out)
			}
		}
	}
	for kind := range ruleCases {
		if !seen[kind] {
			t.Errorf("a case for %s, which is no rule", kind)
		}
	}
}

// Only the secret is replaced: a header's name, a URL's scheme and host, a key's name stay.
func TestOnlyTheSecretIsReplaced(t *testing.T) {
	s := NewScrubber()
	for in, want := range map[string]string{
		"Authorization: Bearer opaque-token-value-123": "Authorization: Bearer [redacted:authorization-header]",
		"https://user:pw-1234@github.com/x":            "https://[redacted:url-credentials]@github.com/x",
		"password=hunter2hunter2 rest":                 "password=[redacted:credential-assignment] rest",
	} {
		if got := s.Scrub(in); got != want {
			t.Errorf("%q scrubbed to %q, want %q", in, got, want)
		}
	}
}

// Claude Code's stream-json survives: its usage numbers, tool names and paths are no secrets.
func TestOrdinaryLinesSurvive(t *testing.T) {
	s := NewScrubber("a-known-secret-value")
	for _, line := range []string{
		`{"type":"result","subtype":"success","usage":{"input_tokens":12345,"output_tokens":678,"cache_creation_input_tokens":90123}}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/repo/internal/x.go"}}]}}`,
		`{"type":"system","subtype":"init","model":"glm-5.3-flash","tools":["Bash","Read","Edit"]}`,
		"ok  \tgithub.com/ryanymt/mercurio-project/internal/runner\t5.4s",
	} {
		if got := s.Scrub(line); got != line {
			t.Errorf("an ordinary line changed:\n%s\n%s", line, got)
		}
	}
}

// A value the runner knows to be secret is redacted wherever it appears: as itself, and in standard
// or URL-safe base64 at any offset, as git's basic credentials carry it. Values too short to be
// told from ordinary text are not taken (P05's leak check, cloudruntest.Leaks).
func TestKnownValuesAreRedactedWhereverTheyAppear(t *testing.T) {
	token := "ghs_" + "fakeInstallationToken" + "0000000042" // P05's fake shape, which no rule matches
	s := NewScrubber(token, "short", "")
	std, url := base64.StdEncoding.EncodeToString, base64.URLEncoding.EncodeToString
	for name, text := range map[string]string{
		"raw":                  "the token " + token + " is used",
		"in a command":         "git -c http.extraHeader=Bearer-" + token + " push",
		"standard base64":      std([]byte(token)),
		"URL-safe base64":      url([]byte(token)),
		"inside basic auth":    "Authorization: basic " + std([]byte("x-access-token:"+token)),
		"git's config value":   "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic " + std([]byte("x-access-token:"+token)),
		"at offset 1, URL":     url([]byte("a" + token + "zz")),
		"at offset 2, std":     std([]byte("ab" + token + "q")),
		"twice in one line":    token + " and " + token,
		"inside a JSON string": `{"output":"remote: ` + token + `"}`,
	} {
		out := s.Scrub(text)
		if leaks := cloudruntest.Leaks(out, token); len(leaks) > 0 {
			t.Errorf("%s: %v left in %q", name, leaks, out)
		}
		if !strings.Contains(out, "[redacted:") {
			t.Errorf("%s: nothing marked redacted in %q", name, out)
		}
	}
	if got := s.Scrub("a short word"); got != "a short word" {
		t.Errorf("a short known value was taken: %q", got)
	}
}

// A known value whose base64 holds the characters standard and URL-safe base64 spell differently
// (+ and /, - and _) is redacted in both, at every offset.
func TestKnownValuesInBothBase64Alphabets(t *testing.T) {
	secret := "pass>>>word???value>>>" // ">>>" encodes with +, "???" with /
	if std, url := base64.StdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)); std == url {
		t.Fatal("this value's two encodings are alike, so the test could not tell them apart")
	}
	s := NewScrubber(secret)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for k := 0; k < 3; k++ {
			blob := enc.EncodeToString([]byte(strings.Repeat("x", k) + secret + "yz"))
			if leaks := cloudruntest.Leaks(s.Scrub(blob), secret); len(leaks) > 0 {
				t.Errorf("%v left in %q", leaks, s.Scrub(blob))
			}
		}
	}
}

// A secret inside an escaped JSON string leaves the line valid JSON: no rule takes the escape of the
// quote that closes it.
func TestRedactionKeepsJSONLinesValid(t *testing.T) {
	jwt := b64url(`{"alg":"ES256","typ":"JWT","kid":"1"}`) + "." + b64url(`{"email":"a@example.com","aud":"x"}`) + "." + rep("sigSIG012_", 3)
	s := NewScrubber("known-secret-value-1234")
	for _, secret := range []string{
		jwt, "ghp_" + rep("aB3d", 9), "AIza" + rep("q", 35), "https://user:pw-1234@github.com/x",
		"Authorization: Bearer opaque-token-value-123", "password=hunter2hunter2", "known-secret-value-1234",
		`-----BEGIN PRIVATE KEY-----\n` + keyBody + `\n-----END PRIVATE KEY-----`, // escaped newlines
	} {
		// The secret, quoted inside a string inside the line, as a tool's output carries it.
		line := `{"type":"tool_result","content":"the value is \"` + secret + `\" here"}`
		if !json.Valid([]byte(line)) {
			t.Fatalf("the test's own line is not JSON: %s", line)
		}
		if out := s.Scrub(line); !json.Valid([]byte(out)) {
			t.Errorf("scrubbing broke the line:\n%s\n%s", line, out)
		}
	}
}
