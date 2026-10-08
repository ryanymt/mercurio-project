package viewer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Transcripts are harness-neutral (P06 D22). A runner stores its harness's own lines, untranslated,
// behind a first line naming the harness, its version and its format. The viewer maps them through
// that harness's adapter into one step model, and shows a transcript no adapter reads as raw lines.
// Another harness is one adapter more; nothing else changes. No line is ever dropped: each gives at
// least one step, and a line an adapter does not understand is a raw step.

// Header is a transcript's first line.
type Header struct {
	Harness string `json:"harness"`
	Version string `json:"version"`
	Format  string `json:"format"`
}

// StepKind is what a step is, whatever harness wrote it.
type StepKind string

const (
	StepSession StepKind = "session" // a harness's start: its model and tools
	StepPrompt  StepKind = "prompt"  // what the agent was asked
	StepText    StepKind = "text"    // the agent's own words
	StepCommand StepKind = "command" // a shell command it ran
	StepEdit    StepKind = "edit"    // a file it changed, as a diff
	StepTool    StepKind = "tool"    // any other tool call
	StepResult  StepKind = "result"  // what a command or tool gave back
	StepEvent   StepKind = "event"   // a step of a scripted runner's own
	StepTest    StepKind = "test"    // a test and its outcome
	StepUsage   StepKind = "usage"   // the run's turns, time and tokens
	StepMeta    StepKind = "meta"    // a known event of little interest by itself, shown folded
	StepRaw     StepKind = "raw"     // a line no adapter reads, shown as it is
)

// DiffLine is one line of an edit: ' ' kept, '-' removed, '+' added.
type DiffLine struct {
	Op   byte
	Text string
}

// Step is one entry of a timeline.
type Step struct {
	Kind  StepKind
	Line  int // the transcript line it came from
	Title string
	Body  string
	Diff  []DiffLine
	Error bool
	Raw   string // the line as stored, for raw and meta steps
}

// DiffText is the step's diff as unified-diff lines.
func (s Step) DiffText() string {
	var b strings.Builder
	for _, d := range s.Diff {
		b.WriteByte(d.Op)
		b.WriteString(d.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

// Timeline is a transcript turned into steps.
type Timeline struct {
	Header  *Header // nil when the first line is no header
	Adapter string  // "harness/format", or "" when every line is shown raw
	Steps   []Step
}

type adapter func(line int, raw string) []Step

var adapters = map[string]adapter{
	"claude-code/stream-json": claudeCode,
	"echo-runner/echo-steps":  echoRunner,
}

// ParseTranscript reads a transcript's lines.
func ParseTranscript(lines []string) Timeline {
	var tl Timeline
	first := 0
	if len(lines) > 0 {
		var h Header
		if json.Unmarshal([]byte(lines[0]), &h) == nil && h.Harness != "" && h.Format != "" {
			tl.Header, first = &h, 1
		}
	}
	read := raw
	if tl.Header != nil {
		key := tl.Header.Harness + "/" + tl.Header.Format
		if a, ok := adapters[key]; ok {
			tl.Adapter, read = key, a
		}
	}
	for i := first; i < len(lines); i++ {
		steps := read(i, lines[i])
		if len(steps) == 0 {
			steps = raw(i, lines[i])
		}
		tl.Steps = append(tl.Steps, steps...)
	}
	return tl
}

// Filter keeps the steps holding q, case-insensitively; an empty q keeps all.
func (t Timeline) Filter(q string) Timeline {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return t
	}
	out := Timeline{Header: t.Header, Adapter: t.Adapter}
	for _, s := range t.Steps {
		if strings.Contains(strings.ToLower(s.Title+"\n"+s.Body+"\n"+s.Raw+"\n"+s.DiffText()), q) {
			out.Steps = append(out.Steps, s)
		}
	}
	return out
}

func raw(line int, s string) []Step {
	return []Step{{Kind: StepRaw, Line: line, Title: "raw", Raw: s}}
}

func meta(line int, title, s string) Step {
	return Step{Kind: StepMeta, Line: line, Title: title, Raw: s}
}

// --- Claude Code's stream-json -------------------------------------------------------------------

type claudeEvent struct {
	Type    string          `json:"type"`
	Subtype string          `json:"subtype"`
	Message json.RawMessage `json:"message"`
	// system/init
	Model string   `json:"model"`
	Tools []string `json:"tools"`
	Cwd   string   `json:"cwd"`
	// result
	NumTurns   int     `json:"num_turns"`
	DurationMS int64   `json:"duration_ms"`
	CostUSD    float64 `json:"total_cost_usd"`
	IsError    bool    `json:"is_error"`
	Result     string  `json:"result"`
	Usage      struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
		CacheRead    int64 `json:"cache_read_input_tokens"`
		CacheWrite   int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

type claudeBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	Thinking string          `json:"thinking"`
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Content  json.RawMessage `json:"content"`
	IsError  bool            `json:"is_error"`
}

// claudeCode reads one line of `claude -p --output-format stream-json --verbose`.
func claudeCode(line int, s string) []Step {
	var e claudeEvent
	if json.Unmarshal([]byte(s), &e) != nil || e.Type == "" {
		return nil
	}
	switch e.Type {
	case "system":
		if e.Subtype == "init" {
			return []Step{{Kind: StepSession, Line: line, Title: "session started",
				Body: fmt.Sprintf("model %s\ntools %s\ndirectory %s", e.Model, strings.Join(e.Tools, ", "), e.Cwd), Raw: s}}
		}
		return []Step{meta(line, "system: "+e.Subtype, s)}
	case "rate_limit_event":
		return []Step{meta(line, "rate limit", s)}
	case "result":
		return []Step{{Kind: StepUsage, Line: line, Title: "run " + e.Subtype, Error: e.IsError,
			Body: fmt.Sprintf("turns %d, %.1f s; tokens in %d, out %d, cache read %d, cache written %d\n%s",
				e.NumTurns, float64(e.DurationMS)/1000, e.Usage.InputTokens, e.Usage.OutputTokens,
				e.Usage.CacheRead, e.Usage.CacheWrite, e.Result)}}
	case "assistant", "user":
		return claudeMessage(line, e.Type, e.Message, s)
	}
	return nil // an event this adapter does not know: shown raw
}

func claudeMessage(line int, role string, msg json.RawMessage, s string) []Step {
	var m struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(msg, &m) != nil {
		return nil
	}
	var text string
	if json.Unmarshal(m.Content, &text) == nil {
		return []Step{{Kind: StepPrompt, Line: line, Title: "prompt", Body: text}}
	}
	var blocks []claudeBlock
	if json.Unmarshal(m.Content, &blocks) != nil {
		return nil
	}
	var steps []Step
	for _, b := range blocks {
		switch {
		case b.Type == "text" && role == "assistant":
			steps = append(steps, Step{Kind: StepText, Line: line, Title: "the agent", Body: b.Text})
		case b.Type == "text":
			steps = append(steps, Step{Kind: StepPrompt, Line: line, Title: "prompt", Body: b.Text})
		case b.Type == "thinking" || b.Type == "redacted_thinking":
			st := meta(line, "thinking", s)
			st.Body = b.Thinking
			steps = append(steps, st)
		case b.Type == "tool_use":
			steps = append(steps, claudeTool(line, b))
		case b.Type == "tool_result":
			steps = append(steps, claudeResult(line, b))
		default:
			steps = append(steps, Step{Kind: StepRaw, Line: line, Title: "raw", Raw: s})
		}
	}
	return steps
}

func claudeTool(line int, b claudeBlock) Step {
	var in map[string]any
	json.Unmarshal(b.Input, &in)
	str := func(k string) string { v, _ := in[k].(string); return v }
	switch b.Name {
	case "Bash":
		return Step{Kind: StepCommand, Line: line, Title: str("command"), Body: str("description")}
	case "Edit":
		return Step{Kind: StepEdit, Line: line, Title: str("file_path"), Diff: diff(str("old_string"), str("new_string"))}
	case "Write":
		return Step{Kind: StepEdit, Line: line, Title: str("file_path") + " (written whole)", Diff: diff("", str("content"))}
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var body []string
	for _, k := range keys {
		v, _ := json.Marshal(in[k])
		body = append(body, k+": "+string(v))
	}
	title := b.Name
	if p := str("file_path"); p != "" {
		title += " " + p
	} else if p := str("pattern"); p != "" {
		title += " " + p
	}
	return Step{Kind: StepTool, Line: line, Title: title, Body: strings.Join(body, "\n")}
}

func claudeResult(line int, b claudeBlock) Step {
	var text string
	if json.Unmarshal(b.Content, &text) != nil {
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		json.Unmarshal(b.Content, &parts)
		var t []string
		for _, p := range parts {
			if p.Type == "text" {
				t = append(t, p.Text)
			}
		}
		text = strings.Join(t, "\n")
	}
	title := "result"
	if b.IsError {
		title = "result: error"
	}
	if strings.Contains(text, "<persisted-output>") {
		title += " (truncated: Claude Code saved the whole output to a file and showed a preview)"
	}
	return Step{Kind: StepResult, Line: line, Title: title, Body: text, Error: b.IsError}
}

// diff shows an edit as its kept head and tail around the lines removed and added.
func diff(old, new string) []DiffLine {
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	}
	a, b := split(old), split(new)
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	var out []DiffLine
	for _, l := range a[:head] {
		out = append(out, DiffLine{' ', l})
	}
	for _, l := range a[head : len(a)-tail] {
		out = append(out, DiffLine{'-', l})
	}
	for _, l := range b[head : len(b)-tail] {
		out = append(out, DiffLine{'+', l})
	}
	for _, l := range a[len(a)-tail:] {
		out = append(out, DiffLine{' ', l})
	}
	return out
}

// --- the echo runner's steps ---------------------------------------------------------------------

// echoRunner reads one line the echo runner wrote: a step ({"step": …}) or a test ({"test": …}).
func echoRunner(line int, s string) []Step {
	var fields map[string]any
	if json.Unmarshal([]byte(s), &fields) != nil {
		return nil
	}
	rest := func(skip ...string) string {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
	next:
		for _, k := range keys {
			for _, sk := range skip {
				if k == sk {
					continue next
				}
			}
			out = append(out, fmt.Sprintf("%s: %v", k, fields[k]))
		}
		return strings.Join(out, "\n")
	}
	if step, ok := fields["step"].(string); ok {
		title := step
		if check, ok := fields["check"].(string); ok {
			title += ": " + check
		}
		return []Step{{Kind: StepEvent, Line: line, Title: title, Body: rest("step"), Error: step == "stopped"}}
	}
	if test, ok := fields["test"].(string); ok {
		passed, _ := fields["ok"].(bool)
		return []Step{{Kind: StepTest, Line: line, Title: test, Body: rest("test"), Error: !passed}}
	}
	return nil
}
