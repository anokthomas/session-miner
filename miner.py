"""session-miner: deterministic detectors over opencode local history.

Reads opencode.db read-only, extracts ordered tool turns per session,
runs Belay-style detectors, writes miner.db + prints a cited report.

Stdlib only. Secrets scrubbed before excerpts are stored/printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path

# --- normalization (mirrors Belay whitepaper §4: volatile values removed) ---

_HEX = re.compile(r"\b[0-9a-f]{7,64}\b", re.IGNORECASE)
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_NUM = re.compile(r"\b\d+(\.\d+)?\b")
_ABS_PATH = re.compile(r"(/(Users|home|tmp|var|private|opt|usr|home)[^\s'\"]*|~[^\s'\"]*)")
_PORT = re.compile(r":\d{2,5}\b")
_WS = re.compile(r"\s+")

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9-_]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{10,}"),
    re.compile(r"gho_[A-Za-z0-9_]{10,}"),
    re.compile(r"xox[bap]-?[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
]

VERIFY_RE = re.compile(
    r"(pytest|unittest|npm test|npx jest|vitest|go test|cargo test|"
    r"tsc\b|eslint|ruff|mypy|pyright|make test|gradle.*test|flutter test)",
    re.IGNORECASE,
)


def scrub(text: str) -> str:
    for rx in _SECRET_PATTERNS:
        text = rx.sub("[REDACTED]", text)
    return text


def cap(text: str, limit: int = 16 * 1024) -> str:
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return text[:head] + "\n…[TRUNCATED]…\n" + text[-tail:]


def normalize_command(cmd: str) -> str:
    cmd = cmd.strip()
    cmd = _ABS_PATH.sub("<PATH>", cmd)
    cmd = _UUID.sub("<ID>", cmd)
    cmd = _HEX.sub("<HASH>", cmd)
    cmd = _PORT.sub(":<PORT>", cmd)
    cmd = _NUM.sub("<N>", cmd)
    cmd = _WS.sub(" ", cmd)
    return cmd.lower()


def fingerprint(project: str, normalized: str) -> str:
    h = hashlib.sha256(f"{project}|{normalized}".encode()).hexdigest()[:16]
    return f"fp_{h}"


def normalize_error(output: str) -> str:
    """First error-ish lines, normalized. Empty string if no error signal."""
    if not output:
        return ""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    sig = [ln for ln in lines if re.search(
        r"(?i)(error|failed|failure|traceback|exception|E\d{3,4}|FAIL\b|panic)", ln)]
    if not sig:
        return ""
    norm = normalize_command(" ".join(sig[:2]))
    if len(norm) < 20:
        return ""  # hash-only fragments, not actionable errors
    return norm[:300]


# --- extraction ---

def load_sessions(src: Path):
    con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    sessions = list(con.execute(
        "SELECT id, project_id, directory, title, model, cost,"
        " tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,"
        " time_created, time_updated FROM session ORDER BY time_created"))
    return con, sessions


def load_tool_turns(con) -> dict:
    """session_id -> list of ordered tool turns."""
    turns: dict = {}
    q = ("SELECT session_id, time_created, data FROM part "
         "ORDER BY session_id, time_created")
    for row in con.execute(q):
        try:
            d = json.loads(row["data"])
        except Exception:
            continue
        if d.get("type") != "tool":
            continue
        state = d.get("state", {}) or {}
        inp = state.get("input", {}) or {}
        tool = d.get("tool", "?")
        cmd = inp.get("command", "") if isinstance(inp, dict) else ""
        fpath = (inp.get("filePath") or inp.get("path") or "") if isinstance(inp, dict) else ""
        out = state.get("output", "") or ""
        if not isinstance(out, str):
            out = json.dumps(out)[:4000]
        status = state.get("status", "")
        t = state.get("time", {}) or {}
        turns.setdefault(row["session_id"], []).append({
            "time": row["time_created"],
            "tool": tool,
            "command": cmd if isinstance(cmd, str) else "",
            "file": fpath if isinstance(fpath, str) else "",
            "output": out if isinstance(out, str) else "",
            "status": status,
            "t_start": t.get("start"),
            "t_end": t.get("end"),
        })
    return turns


# --- detectors ---

def detect_retry_loop(turns, project: str, window: int = 30, threshold: int = 3):
    """Same normalized bash command >= threshold within a window."""
    findings = []
    cmds = [(i, normalize_command(t["command"]))
            for i, t in enumerate(turns) if t["tool"] == "bash" and t["command"].strip()]
    for start in range(len(cmds)):
        bucket: dict = {}
        idxs: dict = {}
        for k in range(start, min(start + window, len(cmds))):
            pos, norm = cmds[k]
            bucket[norm] = bucket.get(norm, 0) + 1
            idxs.setdefault(norm, []).append(pos)
            if bucket[norm] == threshold:
                findings.append({
                    "kind": "retry_loop",
                    "normalized": norm,
                    "fingerprint": fingerprint(project, "retry:" + norm),
                    "span": (idxs[norm][0], idxs[norm][-1]),
                    "turns": list(idxs[norm]),
                })
                break
    # dedupe by fingerprint keeping earliest span
    seen = {}
    for f in findings:
        if f["fingerprint"] not in seen:
            seen[f["fingerprint"]] = f
    return list(seen.values())


def detect_file_thrash(turns, project: str, threshold: int = 4):
    counts: dict = {}
    order: dict = {}
    for i, t in enumerate(turns):
        if t["tool"] in ("edit", "write") and t["file"]:
            counts[t["file"]] = counts.get(t["file"], 0) + 1
            order.setdefault(t["file"], []).append(i)
    out = []
    for f, n in counts.items():
        if n >= threshold:
            out.append({
                "kind": "file_thrash",
                "normalized": f,
                "fingerprint": fingerprint(project, "thrash:" + f),
                "span": (order[f][0], order[f][-1]),
                "turns": order[f],
                "count": n,
            })
    return out


CODE_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
              ".rb", ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift",
              ".kt", ".kts", ".sh", ".sql")


def _is_code_file(path: str) -> bool:
    p = (path or "").lower().split("?")[0]
    return p.endswith(CODE_EXTS)


def detect_done_without_verification(turns, project: str):
    edits = [i for i, t in enumerate(turns)
             if t["tool"] in ("edit", "write") and _is_code_file(t["file"])]
    if not edits:
        return []  # docs-only sessions (e.g. *.md) don't require test commands
    has_verify = any(t["tool"] == "bash" and VERIFY_RE.search(t["command"] or "")
                     for t in turns)
    if not has_verify:
        return [{
            "kind": "done_without_verification",
            "normalized": "edit-without-test",
            "fingerprint": fingerprint(project, "noverify"),
            "span": (edits[0], len(turns) - 1),
            "turns": edits,
        }]
    return []


def detect_recurring_error(per_session_turns: dict, session_project: dict):
    """Same normalized error in >=2 sessions of one project."""
    err_to_sessions: dict = {}
    err_example: dict = {}
    for sid, turns in per_session_turns.items():
        proj = session_project.get(sid, "?")
        seen_here = set()
        for i, t in enumerate(turns):
            if t["tool"] != "bash":
                continue  # read/edit outputs contain the word "error" in source;
                # only shell output is failure evidence
            sig = normalize_error(t["output"])
            if not sig:
                continue
            key = (proj, sig)
            if key not in seen_here:
                seen_here.add(key)
                err_to_sessions.setdefault(key, []).append((sid, i))
                err_example.setdefault(key, t["output"][:500])
    out = []
    for (proj, sig), occ in err_to_sessions.items():
        if len({s for s, _ in occ}) >= 2:
            out.append({
                "kind": "recurring_error",
                "project": proj,
                "normalized": sig,
                "fingerprint": fingerprint(proj, "err:" + sig),
                "sessions": sorted({s for s, _ in occ}),
                "occurrences": occ[:10],
            })
    return out


# --- persistence + report ---

PRICE_PER_MTOK = {  # input, output $/1M tokens; unknown model -> unknown
    "anthropic/claude-opus-4-6": (15.0, 75.0),
    "anthropic/claude-sonnet-4-6": (3.0, 15.0),
    "openai/gpt-5.6": (10.0, 30.0),
}


def estimate_cost(model: str, inp: int, outp: int):
    if model not in PRICE_PER_MTOK:
        return None
    pi, po = PRICE_PER_MTOK[model]
    return (inp / 1e6) * pi + (outp / 1e6) * po


def build_miner_db(out_path: Path, sessions, turns, issues):
    if out_path.exists():
        out_path.unlink()
    con = sqlite3.connect(out_path)
    con.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY, project TEXT, title TEXT,"
                " model TEXT, cost REAL, tokens_in INT, tokens_out INT, turns INT)")
    con.execute("CREATE TABLE tool_turns(session_id TEXT, idx INT, tool TEXT,"
                " command TEXT, file TEXT, excerpt TEXT)")
    con.execute("CREATE TABLE issues(kind TEXT, fingerprint TEXT, project TEXT,"
                " sessions TEXT, span TEXT, cites TEXT)")
    for s in sessions:
        sid = s["id"]
        n = len(turns.get(sid, []))
        con.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)",
                    (sid, s["project_id"], s["title"], s["model"], s["cost"],
                     s["tokens_input"], s["tokens_output"], n))
        for i, t in enumerate(turns.get(sid, [])):
            excerpt = scrub(cap(f"$ {t['command'] or ''}\n"
                                f"[{t['tool']}] {t['file']}\n{t['output'][:2000]}"))
            con.execute("INSERT INTO tool_turns VALUES(?,?,?,?,?,?)",
                        (sid, i, t["tool"], t["command"][:1000], t["file"][:500], excerpt))
    for iss in issues:
        con.execute("INSERT INTO issues VALUES(?,?,?,?,?,?)",
                    (iss["kind"], iss["fingerprint"], iss.get("project", ""),
                     json.dumps(iss.get("sessions", [])),
                     json.dumps(iss.get("span", [])),
                     json.dumps(iss.get("cites", [])[:5])))
    con.commit()
    con.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="path to opencode.db (opened read-only)")
    ap.add_argument("--out", default="miner.db")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()

    src = Path(args.db).expanduser()
    con, sessions = load_sessions(src)
    turns = load_tool_turns(con)
    session_project = {s["id"]: (s["project_id"] or s["directory"] or "?") for s in sessions}
    con.close()

    issues = []
    for s in sessions:
        sid = s["id"]
        proj = session_project[sid]
        st = turns.get(sid, [])
        if not st:
            continue
        for f in detect_retry_loop(st, proj):
            f["project"] = proj
            f["sessions"] = [sid]
            f["cites"] = [
                {"session": sid, "turn": i,
                 "excerpt": scrub(cap((st[i]["command"] or "")[:800]))}
                for i in f["turns"][:5]]
            issues.append(f)
        for f in detect_file_thrash(st, proj):
            f["project"] = proj
            f["sessions"] = [sid]
            f["cites"] = [
                {"session": sid, "turn": i,
                 "excerpt": scrub(cap((st[i]["file"] or "")[:400]))}
                for i in f["turns"][:5]]
            issues.append(f)
        for f in detect_done_without_verification(st, proj):
            f["project"] = proj
            f["sessions"] = [sid]
            f["cites"] = [
                {"session": sid, "turn": i,
                 "excerpt": scrub(cap((st[i]["file"] or st[i]["command"])[:400]))}
                for i in f["turns"][:5]]
            issues.append(f)
    for f in detect_recurring_error(turns, session_project):
        f["cites"] = [{"session": s, "turn": i,
                       "excerpt": scrub(cap(f["normalized"][:400]))}
                      for s, i in f["occurrences"][:5]]
        issues.append(f)

    build_miner_db(Path(args.out), sessions, turns, issues)

    if args.report:
        total_turns = sum(len(v) for v in turns.values())
        print(f"sessions={len(sessions)} tool_turns={total_turns} issues={len(issues)}")
        by_kind: dict = {}
        for i in issues:
            by_kind[i["kind"]] = by_kind.get(i["kind"], 0) + 1
        print("by_kind=" + json.dumps(by_kind))
        for i in issues[:20]:
            sids = ",".join(i.get("sessions", [])[:3])
            print(f"- {i['kind']} {i['fingerprint']} proj={i.get('project','')[:40]} "
                  f"sessions=[{sids}] span={i.get('span','')}")
            for c in i.get("cites", [])[:3]:
                print(f"    cite {c['session'][:12]} turn={c['turn']}: "
                      f"{c['excerpt'][:160]!r}")


if __name__ == "__main__":
    main()
