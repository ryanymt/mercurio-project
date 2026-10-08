package viewer_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/runner"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

// A transcript's timeline is harness-neutral (P06 D22): its first line names the harness, its
// version and its format; that harness's adapter maps its own lines into one step model; a
// transcript no adapter can read is shown as raw lines. No line is ever dropped.

func fixture(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "claude-code", name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// every checks each line but the header gave at least one step: nothing is dropped.
func every(t *testing.T, lines []string, tl viewer.Timeline) {
	t.Helper()
	seen := map[int]bool{}
	for _, s := range tl.Steps {
		seen[s.Line] = true
	}
	first := 0
	if tl.Header != nil {
		first = 1
	}
	for i := first; i < len(lines); i++ {
		if !seen[i] {
			t.Errorf("line %d gave no step: %.200s", i, lines[i])
		}
	}
}

func find(tl viewer.Timeline, kind viewer.StepKind, contains string) *viewer.Step {
	for i, s := range tl.Steps {
		if s.Kind == kind && strings.Contains(s.Title+"\n"+s.Body+"\n"+s.Raw+"\n"+s.DiffText(), contains) {
			return &tl.Steps[i]
		}
	}
	return nil
}

func count(tl viewer.Timeline, kind viewer.StepKind) int {
	n := 0
	for _, s := range tl.Steps {
		if s.Kind == kind {
			n++
		}
	}
	return n
}

// Claude Code's adapter reads every recorded session (P06 T7): the session's start, the agent's
// words, its commands and edits (as diffs), each tool's result with its errors marked, Claude
// Code's own truncation, and the run's usage; nothing it knows is shown raw.
func TestTheClaudeCodeAdapterReadsEveryFixture(t *testing.T) {
	for _, name := range []string{"multi-turn-edit", "failing-test", "tool-error", "truncated-output"} {
		t.Run(name, func(t *testing.T) {
			lines := fixture(t, name)
			tl := viewer.ParseTranscript(lines)
			if tl.Header == nil || tl.Header.Harness != "claude-code" || tl.Header.Format != "stream-json" ||
				tl.Header.Version != "2.1.283" || tl.Adapter != "claude-code/stream-json" {
				t.Fatalf("header %+v, adapter %q", tl.Header, tl.Adapter)
			}
			every(t, lines, tl)
			if n := count(tl, viewer.StepRaw); n != 0 {
				t.Fatalf("%d steps shown raw from a session the adapter knows", n)
			}
			if s := find(tl, viewer.StepSession, "claude-haiku-4-5-20251001"); s == nil {
				t.Fatal("no session step naming the model")
			}
			if s := find(tl, viewer.StepUsage, "turns"); s == nil {
				t.Fatal("no usage step")
			}
		})
	}
	edit := viewer.ParseTranscript(fixture(t, "multi-turn-edit"))
	checks := []struct {
		kind     viewer.StepKind
		contains string
		err      bool
	}{
		{viewer.StepText, "I'll help you add the `Max` function", false},
		{viewer.StepCommand, "go test ./...", false},
		{viewer.StepEdit, "+func Max(xs []int) (int, bool) {", false},
		{viewer.StepEdit, "-\treturn float64(Sum(xs) / len(xs)), true", false},
		{viewer.StepEdit, "+\treturn float64(Sum(xs)) / float64(len(xs)), true", false},
		{viewer.StepResult, "--- FAIL: TestMean", true},
		{viewer.StepResult, "ok  \texample.com/calc", false},
		{viewer.StepTool, "calc_test.go", false}, // a Read
		{viewer.StepUsage, "turns 11", false},
	}
	for _, c := range checks {
		s := find(edit, c.kind, c.contains)
		if s == nil {
			t.Errorf("multi-turn-edit: no %s step holding %q", c.kind, c.contains)
		} else if s.Error != c.err {
			t.Errorf("multi-turn-edit: the %s step holding %q has error %v", c.kind, c.contains, s.Error)
		}
	}
	if s := find(viewer.ParseTranscript(fixture(t, "failing-test")), viewer.StepResult, "EISDIR"); s == nil || !s.Error {
		t.Error("failing-test: the EISDIR result is not an error step")
	}
	if s := find(viewer.ParseTranscript(fixture(t, "tool-error")), viewer.StepResult, "File does not exist"); s == nil || !s.Error {
		t.Error("tool-error: the failed Read is not an error step")
	}
	trunc := viewer.ParseTranscript(fixture(t, "truncated-output"))
	if s := find(trunc, viewer.StepCommand, "seq 1 20000"); s == nil {
		t.Error("truncated-output: no seq command")
	}
	if s := find(trunc, viewer.StepResult, "Preview (first 2KB)"); s == nil || !strings.Contains(s.Title, "truncated") {
		t.Errorf("truncated-output: the persisted output is not marked truncated with its preview: %+v", s)
	}
}

// An event Claude Code's adapter does not know is shown raw, escaped by the page, never dropped.
func TestAnUnknownEventIsShownRaw(t *testing.T) {
	lines := fixture(t, "unknown-event")
	tl := viewer.ParseTranscript(lines)
	every(t, lines, tl)
	if n := count(tl, viewer.StepRaw); n != 1 {
		t.Fatalf("%d raw steps, want the one made by hand", n)
	}
	if s := find(tl, viewer.StepRaw, `"type":"future_event"`); s == nil || s.Line != 2 {
		t.Fatalf("the unknown event's raw step %+v", s)
	}
}

// A transcript with no header, one naming a harness or format no adapter reads, and a line that is
// not JSON within a known harness are all shown raw.
func TestTranscriptsNoAdapterReadsAreShownRaw(t *testing.T) {
	body := []string{`{"type":"system","subtype":"init","model":"m"}`, `plain text, not JSON`}
	for name, c := range map[string]struct {
		lines  []string
		header bool // the first line is a header, so not shown
	}{
		"no header":           {body, false},
		"another harness":     {append([]string{`{"harness":"codex","version":"0.9","format":"exec-json"}`}, body...), true},
		"another format":      {append([]string{`{"harness":"claude-code","version":"3","format":"protobuf"}`}, body...), true},
		"a header not JSON":   {append([]string{`harness: claude-code`}, body...), false},
		"a header no format":  {append([]string{`{"harness":"claude-code","version":"2"}`}, body...), false},
		"a header no harness": {append([]string{`{"version":"2","format":"stream-json"}`}, body...), false},
	} {
		t.Run(name, func(t *testing.T) {
			tl := viewer.ParseTranscript(c.lines)
			every(t, c.lines, tl)
			if tl.Adapter != "" || count(tl, viewer.StepRaw) != len(tl.Steps) {
				t.Fatalf("adapter %q, steps %+v: want every line raw", tl.Adapter, tl.Steps)
			}
			if (tl.Header != nil) != c.header {
				t.Fatalf("header %+v, want one: %v", tl.Header, c.header)
			}
		})
	}
	known := []string{`{"harness":"claude-code","version":"2","format":"stream-json"}`, `{"type":"system","subtype":"init","model":"m"}`, `not JSON`}
	tl := viewer.ParseTranscript(known)
	if tl.Adapter == "" || count(tl, viewer.StepRaw) != 1 || find(tl, viewer.StepRaw, "not JSON") == nil {
		t.Fatalf("a bad line in a known harness: %+v", tl)
	}
}

// The echo runner's transcript reads through its own adapter: its header names it, each step and
// test is a step, a stopped run and a failed test are errors (P06 D22).
func TestTheEchoAdapterReadsTheEchoRunnersLines(t *testing.T) {
	header := `{"format":"` + runner.TranscriptFormat + `","harness":"` + runner.Harness + `","version":"1"}`
	lines := []string{
		header,
		`{"attempt":1,"branch":"foreman/7/1","run":"0123","step":"started","ticket":7}`,
		`{"check":"get an object","result":"denied","status":403,"step":"probe"}`,
		`{"step":"canary","value":"[redacted:github-app-token]"}`,
		`{"file":"echo/7.txt","ok":true,"test":"echo file"}`,
		`{"file":"echo/7.txt","ok":false,"test":"echo file"}`,
		`{"error":"POST /v1/tickets/7/heartbeat: status 409: refused","step":"stopped"}`,
		`{"something":"else"}`,
	}
	tl := viewer.ParseTranscript(lines)
	if tl.Adapter != "echo-runner/echo-steps" {
		t.Fatalf("adapter %q: the runner's header and the viewer's adapter disagree", tl.Adapter)
	}
	every(t, lines, tl)
	for _, c := range []struct {
		kind     viewer.StepKind
		contains string
		err      bool
	}{
		{viewer.StepEvent, "started", false},
		{viewer.StepEvent, "get an object", false},
		{viewer.StepEvent, "[redacted:github-app-token]", false},
		{viewer.StepTest, "echo file", false},
		{viewer.StepEvent, "status 409", true},
	} {
		if s := find(tl, c.kind, c.contains); s == nil || s.Error != c.err {
			t.Errorf("no %s step holding %q with error %v: %+v", c.kind, c.contains, c.err, s)
		}
	}
	failed := 0
	for _, s := range tl.Steps {
		if s.Kind == viewer.StepTest && s.Error {
			failed++
		}
	}
	if failed != 1 || count(tl, viewer.StepRaw) != 1 {
		t.Fatalf("failed tests %d and raw steps %d, want 1 and 1", failed, count(tl, viewer.StepRaw))
	}
}

// ?q= keeps the steps holding the text, case-insensitively, whatever their kind.
func TestTheTimelineFilters(t *testing.T) {
	tl := viewer.ParseTranscript(fixture(t, "multi-turn-edit"))
	got := tl.Filter("GO TEST")
	if len(got.Steps) == 0 || len(got.Steps) >= len(tl.Steps) {
		t.Fatalf("%d of %d steps kept", len(got.Steps), len(tl.Steps))
	}
	for _, s := range got.Steps {
		if !strings.Contains(strings.ToLower(s.Title+s.Body+s.Raw+s.DiffText()), "go test") {
			t.Fatalf("a step without the text kept: %+v", s)
		}
	}
	if all := tl.Filter(""); len(all.Steps) != len(tl.Steps) {
		t.Fatal("an empty filter dropped steps")
	}
}

// An edit shows its unchanged head and tail around what it removed and added; a file written whole
// is all added.
func TestAnEditShowsWhatChanged(t *testing.T) {
	tl := viewer.ParseTranscript([]string{
		`{"harness":"claude-code","version":"2","format":"stream-json"}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Edit","input":{"file_path":"f.go","old_string":"a\nb\nc\nd\ne","new_string":"a\nX\nY\nd\ne"}}]}}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Write","input":{"file_path":"g.go","content":"one\ntwo\n"}}]}}`,
	})
	if len(tl.Steps) != 2 {
		t.Fatalf("steps %+v", tl.Steps)
	}
	if got := tl.Steps[0].DiffText(); got != " a\n-b\n-c\n+X\n+Y\n d\n e\n" || tl.Steps[0].Title != "f.go" {
		t.Fatalf("the edit %q: %q", tl.Steps[0].Title, got)
	}
	if got := tl.Steps[1].DiffText(); got != "+one\n+two\n" || !strings.Contains(tl.Steps[1].Title, "g.go") {
		t.Fatalf("the write %q: %q", tl.Steps[1].Title, got)
	}
}
