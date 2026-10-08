# Claude Code fixtures

Real Claude Code sessions, for the viewer's Claude Code adapter (P06 T7, D22). Each file is a
transcript as a runner stores it: a header line naming the harness, its version and its format,
then Claude Code's own `--output-format stream-json` lines, untranslated.

```
{"format":"stream-json","harness":"claude-code","version":"2.1.283"}
```

## The sessions

| File | Prompt | What it holds |
|---|---|---|
| `multi-turn-edit.jsonl` | Add `Max` with table tests to a small Go module, run `go test ./...`, fix what fails | 11 turns: reads, two edits, a failing `go test` (an error tool result, exit code 1), a fix to `Mean`, a passing run |
| `failing-test.jsonl` | Run `go test ./...` and say which test fails and why, changing nothing | the failing test's output; a second tool error (`EISDIR`, a directory read as a file); `Glob` results |
| `tool-error.jsonl` | Read `docs/DESIGN.md` and summarize it, without creating it | a `Read` that fails: "File does not exist" |
| `truncated-output.jsonl` | Run `seq 1 20000` and give the last number | Claude Code's truncation: a `<persisted-output>` block with a 2KB preview and the full output saved to a file, then `tail -1` on it |
| `unknown-event.jsonl` | `tool-error.jsonl` with one event added by hand after the init event | a `"type":"future_event"` no adapter knows, to prove it is shown raw |

Besides messages, the sessions carry the event types an adapter meets in practice: `system/init`,
`system/thinking_tokens`, `rate_limit_event`, `result/success`, thinking blocks whose text is empty
and which hold only a signature, and `tool_use_result` side data on tool results.

## How they were recorded

2026-10-06, 15:21 to 15:22 UTC, Claude Code 2.1.283, model `claude-haiku-4-5-20251001`. Each session
ran in its own copy of a scratch Go module (`example.com/calc`: `Sum`, a `Mean` that divides integers,
and their tests, one failing), a git repository outside this project:

```
env -i HOME="$HOME" PATH="$PATH" LANG=C.UTF-8 USER="$USER" \
  claude -p "<prompt>" --output-format stream-json --verbose --model haiku \
    --restricted --strict-mcp-config --no-session-persistence \
    --tools "<tools>" --allowedTools <allowed tools>
```

- `--restricted` ignored user, project and local settings, so no plugin or hook of the operator's
  loaded (the init events list built-in plugins only), and confined the file tools to the module.
- `--strict-mcp-config` with no `--mcp-config`: no MCP servers (`"mcp_servers": []`).
- The environment was built from nothing but `HOME` (the login), `PATH` and the locale, so nothing
  of the session that recorded them reached Claude Code.
- `--tools` and `--allowedTools` per session:
  - the edit: `Read,Edit,Write,Bash,Glob,Grep`, with `go test` and `gofmt` allowed;
  - the failing test: `Read,Bash,Glob`, with `go test` allowed;
  - the tool error: `Read,Glob`;
  - the truncation: `Bash`, with `seq` allowed.
- Claude Code still ran the read-only `ls -la` and `tail -1` without an allowlist entry: it allows
  read-only commands by itself. No permission was denied.
- Cost, by Claude Code's own count: $0.038, $0.032, $0.013 and $0.012.

They were then scrubbed with `internal/capture`'s scrubber, exactly as a runner's capture scrubs. It
changed nothing: no secret was in them, and no rule fired on ordinary stream-json. Then the header
line was prepended. They were read through, the init events first, before staging. The paths in them
are the scratch module's.
