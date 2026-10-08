package viewer_test

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	sha1 = "1111111111111111111111111111111111111111"
	sha2 = "2222222222222222222222222222222222222222"
	sha3 = "3333333333333333333333333333333333333333"
	run  = "0123456789abcdef0123456789abcdef"
)

// Every page needs IAP's assertion for a person the map knows; every response carries the CSP and
// the other security headers (P06 D17).
func TestEveryPageNeedsAValidAssertion(t *testing.T) {
	r := newRig(t)
	r.start()
	id := r.seed("foreman", "a ticket", "ready", nil)
	for _, path := range []string{"/", fmt.Sprintf("/tickets/%d", id), "/whoami", "/static/style.css"} {
		for name, c := range map[string]struct {
			assertion string
			want      int
		}{
			"none":            {"", http.StatusUnauthorized},
			"not a JWT":       {"not.an.assertion", http.StatusUnauthorized},
			"an unknown name": {r.iap.assertion(t, "someone@example.com"), http.StatusForbidden},
			"the operator":    {r.iap.assertion(t, operator), http.StatusOK},
		} {
			st, body := r.request(http.MethodGet, path, nil, c.assertion, nil)
			if st != c.want {
				t.Errorf("%s with %s: status %d, want %d: %.200s", path, name, st, c.want, body)
			}
		}
	}
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/", nil)
	req.Header.Set("X-Goog-Iap-Jwt-Assertion", r.iap.assertion(t, operator))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := resp.Header
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers %v", h)
	}
}

// The list shows tickets by project and state, and filters by either.
func TestTheTicketList(t *testing.T) {
	r := newRig(t)
	r.start()
	r.seed("foreman", "foreman ready one", "ready", nil)
	r.seed("sandbox", "sandbox escalated one", "escalated", map[string]any{"escalated_at": time.Now(), "head_sha": sha1})
	r.seed("sandbox", "sandbox draft one", "draft", nil)
	_, all := r.get("/")
	for _, title := range []string{"foreman ready one", "sandbox escalated one", "sandbox draft one"} {
		if !strings.Contains(all, title) {
			t.Errorf("the list lacks %q", title)
		}
	}
	_, sandbox := r.get("/?project=sandbox")
	if strings.Contains(sandbox, "foreman ready one") || !strings.Contains(sandbox, "sandbox draft one") {
		t.Error("?project=sandbox did not filter")
	}
	_, escalated := r.get("/?state=escalated")
	if strings.Contains(escalated, "sandbox draft one") || !strings.Contains(escalated, "sandbox escalated one") {
		t.Error("?state=escalated did not filter")
	}
}

var runnerText = regexp.MustCompile(`(?s)class="runner-text"[^>]*>.*?</`)

// A ticket's page shows its fields and last escalation, its events and attempts, and its artifacts
// by run. Text a runner wrote is set apart and labelled as the runner's (red team round 2).
func TestATicketsPage(t *testing.T) {
	r := newRig(t)
	r.start()
	at := time.Date(2026, 10, 6, 9, 30, 0, 123456000, time.UTC)
	id := r.seed("sandbox", "echo something", "escalated", map[string]any{"escalated_at": at, "escalation_reason": "tests pass, please approve",
		"head_sha": sha2, "base_sha": sha1, "branch": "foreman/1/1", "attempt_count": 1, "body": "the body text"})
	r.event(id, "claimed", "in_progress", "dev", "dev-sandbox@your-project-id.iam.gserviceaccount.com", `{}`)
	r.event(id, "in_progress", "escalated", "dev", "dev-sandbox@your-project-id.iam.gserviceaccount.com",
		`{"reason": "tests pass, please approve"}`)
	if _, err := r.owner.Exec(`INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, claim_token, outcome)
		VALUES ($1, 1, 'dev', 'zai', 'glm-5.3-flash', 'dev-glm-flash', 'the-live-claim-token', 'completed')`, id); err != nil {
		t.Fatal(err)
	}
	r.artifact(id, 1, "transcript", fmt.Sprintf("sandbox/%d/1/dev-%s/transcript", id, run))
	r.artifact(id, 1, "test_report", fmt.Sprintf("sandbox/%d/1/dev-%s/test_report", id, run))
	st, page := r.get(fmt.Sprintf("/tickets/%d", id))
	if st != http.StatusOK {
		t.Fatalf("status %d: %s", st, page)
	}
	for _, want := range []string{"echo something", "the body text", "escalated", sha2, sha1, "foreman/1/1",
		"2026-10-06T09:30:00.123456Z", "glm-5.3-flash", "dev-glm-flash", "dev-" + run, "transcript", "test_report",
		"dev-sandbox@your-project-id.iam.gserviceaccount.com"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "the-live-claim-token") {
		t.Fatal("the page shows a claim token")
	}
	// The runner's words are set apart and labelled where each is shown: the last escalation, and its
	// event; a person's reason is not.
	section := func(class string) string {
		return regexp.MustCompile(`(?s)<section class="` + class + `">.*?</section>`).FindString(page)
	}
	for _, class := range []string{"escalation", "events"} {
		s := section(class)
		labelled := false
		for _, m := range runnerText.FindAllString(s, -1) {
			labelled = labelled || strings.Contains(m, "tests pass, please approve")
		}
		if !labelled || !strings.Contains(s, "written by the dev runner") {
			t.Errorf("the %s section does not set the runner's reason apart: %s", class, s)
		}
	}
	// A person's parking is a same-state event: it neither takes the label from the runner's reason
	// nor gives its own reason one.
	r.event(id, "escalated", "escalated", "human", operator, `{"reason": "a person's own note", "parked": true}`)
	_, page = r.get(fmt.Sprintf("/tickets/%d", id))
	for _, m := range runnerText.FindAllString(section("events"), -1) {
		if strings.Contains(m, "a person's own note") {
			t.Fatalf("a person's reason labelled as a runner's: %s", m)
		}
	}
	if s := section("escalation"); !strings.Contains(s, "written by the dev runner") {
		t.Fatalf("after a person parked it, the escalation's reason is no longer the runner's: %s", s)
	}
}

// The verdict is shown only for the commit it names: base, head and tested commit all the ticket's.
// A stale one, or an event payload shaped like one, is never shown as the verdict (red team R1,
// R9#2; [P03/review2]).
func TestTheVerdictIsShownOnlyForItsCommit(t *testing.T) {
	r := newRig(t)
	r.start()
	verdict := func(base, head, tested string) string {
		return fmt.Sprintf(`{"cleared": true, "matched_rules": ["rule-shown-%s"], "evaluated_at": "2026-10-06T09:00:00Z",
			"base_sha": %q, "head_sha": %q, "tested_sha": %q}`, head[:4], base, head, tested)
	}
	for name, c := range map[string]struct {
		verdict string
		shown   bool
	}{
		"its own commit":     {verdict(sha1, sha2, sha2), true},
		"a stale head":       {verdict(sha1, sha3, sha3), false},
		"a stale base":       {verdict(sha3, sha2, sha2), false},
		"another tested sha": {verdict(sha1, sha2, sha3), false},
		"another head":       {verdict(sha1, sha3, sha2), false},
		"none":               {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			set := map[string]any{"head_sha": sha2, "base_sha": sha1, "escalated_at": time.Now()}
			if c.verdict != "" {
				set["risk_verdict"] = c.verdict
			}
			id := r.seed("foreman", "verdict "+name, "escalated", set)
			// A runner's payload imitating a verdict, on another transition.
			r.event(id, "in_progress", "awaiting_review", "dev", "dev-foreman@your-project-id.iam.gserviceaccount.com",
				`{"risk_verdict": {"cleared": true, "matched_rules": ["imitation-rule"]}}`)
			_, page := r.get(fmt.Sprintf("/tickets/%d", id))
			verdictPanel := regexp.MustCompile(`(?s)<section class="verdict">.*?</section>`).FindString(page)
			if verdictPanel == "" {
				t.Fatal("no verdict section")
			}
			if strings.Contains(verdictPanel, "imitation-rule") {
				t.Fatal("an event payload shown as the verdict")
			}
			if c.shown != strings.Contains(verdictPanel, "rule-shown-") || c.shown == strings.Contains(verdictPanel, "no verdict for this commit") {
				t.Fatalf("verdict section %q, want shown %v", verdictPanel, c.shown)
			}
		})
	}
}

// An attempt's timeline: its chunks read in order through the transcript's adapter, collapsible, the
// agent's markup inert, filtered by ?q=; the echo runner's own stream likewise.
func TestTheTimeline(t *testing.T) {
	r := newRig(t)
	r.start()
	id := r.seed("sandbox", "a timeline", "awaiting_review", map[string]any{"head_sha": sha2, "attempt_count": 1})
	prefix := fmt.Sprintf("sandbox/%d/1/dev-%s/transcript", id, run)
	aid := r.artifact(id, 1, "transcript", prefix)
	b, err := os.ReadFile(filepath.Join("testdata", "claude-code", "multi-turn-edit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(strings.TrimRight(string(b), "\n"), "\n")
	half := len(lines) / 2
	r.chunks.put(prefix+"/000001.jsonl", strings.Join(lines[:half], ""))
	r.chunks.put(prefix+"/000002.jsonl", strings.Join(lines[half:], "")+"\n"+
		`{"type":"assistant","message":{"content":[{"type":"text","text":"<script>alert(1)</script> and <b>bold</b>"}]}}`+"\n")
	st, page := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d", id, aid))
	if st != http.StatusOK {
		t.Fatalf("status %d: %s", st, page)
	}
	text := html.UnescapeString(page) // html/template escapes + and ' too
	for _, want := range []string{"claude-code/stream-json", "2.1.283", "go test ./...", "+func Max(xs []int) (int, bool) {",
		"--- FAIL: TestMean"} {
		if !strings.Contains(text, want) {
			t.Errorf("the timeline lacks %q", want)
		}
	}
	for _, want := range []string{"<details", "&lt;script&gt;alert(1)&lt;/script&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("the timeline's markup lacks %q", want)
		}
	}
	if strings.Contains(page, "<script>alert(1)") || strings.Contains(page, "<b>bold</b>") {
		t.Fatal("the agent's markup rendered")
	}
	_, filtered := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d?q=FAIL", id, aid))
	if !strings.Contains(filtered, "--- FAIL: TestMean") || strings.Contains(filtered, "I&#39;ll help you add") {
		t.Fatal("?q=FAIL did not filter the steps")
	}

	echo := fmt.Sprintf("sandbox/%d/1/dev-%s/test_report", id, run)
	eid := r.artifact(id, 1, "test_report", echo)
	r.chunks.put(echo+"/000001.jsonl", `{"format":"echo-steps","harness":"echo-runner","version":"1"}`+"\n"+
		`{"file":"echo/1.txt","ok":false,"test":"echo file"}`+"\n")
	_, report := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d", id, eid))
	if !strings.Contains(report, "echo-runner/echo-steps") || !strings.Contains(report, "echo file") || !strings.Contains(report, "failed") {
		t.Fatalf("the echo runner's report: %s", report)
	}
}

// The viewer reads at most MaxChunks objects of a prefix and MaxChunkBytes of each, and says what it
// left out: a runner's output never decides how much the viewer loads.
// An artifact page reads at most its byte budget across all its chunks and says where it stopped:
// a chunk is read only up to what the budget has left, and none after it is asked for (the
// validation round: a real session's transcript must not exhaust the viewer's memory).
func TestAPageReadsAtMostItsBudget(t *testing.T) {
	r := newRig(t)
	r.cfg.MaxPageBytes = 100
	r.start()
	id := r.seed("sandbox", "budget", "awaiting_review", map[string]any{"attempt_count": 1})
	prefix := fmt.Sprintf("sandbox/%d/1/dev-%s/transcript", id, run)
	aid := r.artifact(id, 1, "transcript", prefix)
	r.chunks.put(prefix+"/000001.jsonl", `{"step":"one `+strings.Repeat("a", 40)+`"}`+"\n") // 56 bytes
	r.chunks.put(prefix+"/000002.jsonl", `{"step":"two `+strings.Repeat("b", 80)+`"}`+"\n") // 96 bytes
	r.chunks.put(prefix+"/000003.jsonl", `{"step":"three"}`+"\n")
	_, page := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d", id, aid))
	if !strings.Contains(page, strings.Repeat("a", 40)) || !strings.Contains(page, "only the first 100 bytes of this artifact are read") ||
		!strings.Contains(page, "000002.jsonl truncated at 44 bytes") || strings.Contains(page, "three") {
		t.Fatalf("the page's budget is not kept or not stated: %s", page)
	}
	if r.chunks.reads != 2 {
		t.Fatalf("%d objects read, want 2", r.chunks.reads)
	}
}

func TestChunkReadsAreBounded(t *testing.T) {
	r := newRig(t)
	r.cfg.MaxChunks, r.cfg.MaxChunkBytes = 2, 120
	r.start()
	id := r.seed("sandbox", "bounded", "awaiting_review", map[string]any{"attempt_count": 1})
	prefix := fmt.Sprintf("sandbox/%d/1/dev-%s/transcript", id, run)
	aid := r.artifact(id, 1, "transcript", prefix)
	r.chunks.put(prefix+"/000001.jsonl", `{"step":"one"}`+"\n")
	r.chunks.put(prefix+"/000002.jsonl", `{"step":"two `+strings.Repeat("x", 300)+`"}`+"\n")
	r.chunks.put(prefix+"/000003.jsonl", `{"step":"three"}`+"\n")
	_, page := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d", id, aid))
	if !strings.Contains(page, "more chunks not shown") || !strings.Contains(page, "truncated at 120 bytes") ||
		strings.Contains(page, "three") {
		t.Fatalf("the bounds are not stated or not kept: %s", page)
	}
	if r.chunks.reads > 2 {
		t.Fatalf("%d objects read, want at most 2", r.chunks.reads)
	}
}

// An artifact of another ticket is not served under this one.
func TestAnArtifactBelongsToItsTicket(t *testing.T) {
	r := newRig(t)
	r.start()
	a := r.seed("sandbox", "a", "ready", nil)
	b := r.seed("sandbox", "b", "ready", nil)
	aid := r.artifact(a, 1, "transcript", fmt.Sprintf("sandbox/%d/1/dev-%s/transcript", a, run))
	if st, _ := r.get(fmt.Sprintf("/tickets/%d/artifacts/%d", b, aid)); st != http.StatusNotFound {
		t.Fatalf("status %d, want 404", st)
	}
}
