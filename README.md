# session-miner

Deterministic detectors over real agent session history — built from daily
**opencode** use, portable to Belay's Claude Code / Codex pipeline.

I use opencode daily (not Claude Code). opencode stores history in local
SQLite (`~/.local/share/opencode/opencode.db`: `session` / `message` /
`part` tables) instead of Claude's `*.jsonl` transcripts — same idea,
different container. This repo implements Belay-style deterministic analysis
over that store:

* `retry_loop`: same normalized failing bash command ≥3× in a 30-turn window
* `file_thrash`: same file edited/written ≥4× in one session
* `done_without_verification`: edits with no test/build/lint/typecheck command
* `recurring_error`: same normalized error signature in ≥2 sessions, one project

No LLM. Stdlib only. Every finding cites session id + turn time + truncated
excerpt, with secrets scrubbed and 16 KiB head/tail caps (same policy as
Belay's whitepaper §3-4).

## Run (read-only, never writes to your opencode.db)

```bash
python3 miner.py --db ~/.local/share/opencode/opencode.db --out ./miner.db --report
```

Outputs `miner.db` (`sessions`, `tool_turns`, `issues`) + a human report.
The source db is opened `mode=ro`.

## Tests

```bash
python3 -m pytest tests/ -v
# 7 passed
```

## Real run on my opencode history (Sep 2026)

```
sessions=48 tool_turns=1354 issues=51
by_kind={"retry_loop": 11, "file_thrash": 32,
         "done_without_verification": 7, "recurring_error": 1}
```

* Retry loop: `.venv/bin/python -m pytest -v | tail -20` repeated 3× in one
  session (turns 33/72/101) — same normalized command, verification without a
  fix in between.
* Recurring error: `traceback … raise fpdfexception(` in 2 sessions —
  same normalized shell-error signature, cross-session.
* False positive found + fixed: first cut flagged 31 done-without-verification,
  mostly `canon/books/*.md` writes. Docs don't need `pytest`. Scoped the
  detector to code extensions (`.py/.ts/.go/…`) → 7 remaining. Same
  precision-over-recall tradeoff Belay needs for its detectors.

## Go port

`go/detector.go` ports the hot path (normalization + fingerprint + retry-loop)
to Go with stdlib only — the stack Belay hires for. Python ships first for
speed; Go is the production shape.

## Mapping to Belay

| Belay (Claude/Codex JSONL) | This repo (opencode SQLite) |
|---|---|
| `~/.claude/projects/*.jsonl`, Codex `rollout-*.jsonl` | `opencode.db` `session`/`part`, read-only |
| Canonical event stream + encrypted `transcript_turns` | `miner.db` `tool_turns` (local, unencrypted demo) |
| Deterministic detectors + fingerprints | Same rules, same normalization |
| Token-span cost via versioned price table, unknown → unknown | Same; falls back to opencode's recorded `cost` |
| Mission Pack (≤3, approved, scoped) | Not built — proposed as first contribution (see below) |

## What I'd fix first in belay-engine

Close the loop on "prove a fix worked" (docs: counting whether a mistake
comes back is next; whitepaper §11: longitudinal measurement). After a
Mission Pack receipt binds to a destination session, re-run the same
fingerprint detector on that session and record `recurred BOOL + cited turns`
per `delivery_outcomes(receipt_id, fingerprint)`. Per-experience recurrence
rate, no LLM, Go + SQLite only. Second: agent-specific Pack ordering — the
eval shows Claude +5 net vs Codex +0 net, so one template doesn't fit both.
