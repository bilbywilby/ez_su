#!/usr/bin/env bash
# =============================================================================
# repo_audit.sh - read-only git repository auditor (Debian / Crostini / Termux)
#
# NON-DESTRUCTIVE CONTRACT
#   * Never edits, deletes, moves or chmods anything inside an audited repo.
#   * git runs with GIT_OPTIONAL_LOCKS=0 (no index refresh), fsmonitor off,
#     pager off, no prompts. Hooks are never executed (hooks are only parsed).
#   * When run as root (sudo), git/python/shell parsers drop to the repo
#     owner via runuser, so a hostile repo config cannot run code as root.
#   * Only writes: report files under --out (default ~/.repo_audit/reports of
#     the invoking user) and one private mktemp dir (its single rm -rf).
#   * SQLite files open as read-only + immutable; encrypted DBs are only
#     classified, never keyed. Secret scans print file:line, never content.
#
# USAGE   sudo ./repo_audit.sh [options] [PATH ...]      (sudo is optional)
# EXIT    0 clean | 1 warnings | 2 failures | 64 usage | 127 git missing
# =============================================================================
set -u
set -o pipefail
umask 077
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

VERSION="1.0.0"
PROG="repo_audit.sh"

DEPTH=3 MAX_MB=5 QUIET=0 COLOR=1 STRICT=0 REMOTE=0 DEEP=0 HISTORY=0
HASH_TREE=0 REPORT_ON=1 T_SEC=30 OUT_BASE="" IDX=0
PATHS=() SCAN_DIRS=() REPOS=()
declare -A SEEN=()
N_OK=0 N_INFO=0 N_WARN=0 N_FAIL=0
REPO="" REPO_LABEL="-" REPO_OWNER="" OWNER_HOME=""
ASOWNER=() GCMD=()
TMPD="" REPORT="" FINDINGS=""
C_R="" C_G="" C_Y="" C_B="" C_0=""

# --------------------------------------------------------------------------
# Embedded Python helper (stdlib only). Prints: LEVEL<TAB>check<TAB>message
# Run isolated (-I): ignores cwd/env so repo files can never shadow stdlib.
# --------------------------------------------------------------------------
read -r -d '' PYSRC <<'PYEOF' || true
import ast, json, os, re, sqlite3, sys
from collections import Counter
from urllib.parse import quote

MAGIC = b"SQLite format 3\x00"

def out(level, check, msg):
    print("%s\t%s\t%s" % (level, check, " ".join(str(msg).split())))

def paths():
    return [l.rstrip("\n") for l in sys.stdin if l.strip()]

def rel(p, root):
    try:
        r = os.path.relpath(p, root)
        return p if r.startswith("..") else r
    except ValueError:
        return p

def read_bytes(p):
    with open(p, "rb") as f:
        return f.read()

def mode_py(root):
    ps, bad = paths(), 0
    for p in ps:
        try:
            ast.parse(read_bytes(p), filename=p)
        except SyntaxError as e:
            bad += 1
            out("FAIL", "py-syntax", "%s:%s: %s" % (rel(p, root), e.lineno, e.msg))
        except OSError:
            bad += 1
            out("WARN", "unreadable", rel(p, root))
        except Exception as e:
            bad += 1
            out("WARN", "py-syntax", "%s: %s" % (rel(p, root), type(e).__name__))
    if ps and not bad:
        out("OK", "py-syntax", "%d python file(s) parse cleanly" % len(ps))

def mode_json(root):
    ps, bad = paths(), 0
    for p in ps:
        try:
            json.loads(read_bytes(p).decode("utf-8-sig"))
        except OSError:
            bad += 1
            out("WARN", "unreadable", rel(p, root))
        except ValueError as e:
            bad += 1
            out("FAIL", "json-syntax", "%s: %s" % (rel(p, root), e))
    if ps and not bad:
        out("OK", "json-syntax", "%d json file(s) valid" % len(ps))

def mode_sqlite(root):
    for p in paths():
        r = rel(p, root)
        try:
            if os.path.getsize(p) == 0:
                out("INFO", "db", "%s: empty file" % r)
                continue
            with open(p, "rb") as f:
                head = f.read(16)
        except OSError as e:
            out("WARN", "db", "%s: unreadable (%s)" % (r, e.__class__.__name__))
            continue
        if head != MAGIC:
            out("INFO", "db", "%s: not plaintext SQLite (SQLCipher/WCDB/encrypted/other) - classified only, never keyed" % r)
            continue
        try:
            uri = "file:" + quote(os.path.abspath(p), safe="/") + "?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True, timeout=5)
            try:
                res = con.execute("PRAGMA quick_check").fetchall()
                tables = con.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            finally:
                con.close()
            verdict = res[0][0] if res else "no result"
            if verdict == "ok":
                out("OK", "db", "%s: plaintext SQLite, quick_check ok, %d table(s)" % (r, tables))
            else:
                out("FAIL", "db", "%s: quick_check: %s" % (r, verdict))
            wal = p + "-wal"
            if os.path.exists(wal) and os.path.getsize(wal) > 0:
                out("WARN", "db", "%s: non-empty -wal present; immutable open ignores it" % r)
        except sqlite3.Error as e:
            out("FAIL", "db", "%s: sqlite error: %s" % (r, e))

BR = re.compile(r"\[\^?\]?(?:\[:[a-z]+:\]|[^\]\n])*\]")
HOT = re.compile(r"\b(?:grep|egrep|fgrep|sed|awk|gawk|mawk|expr|rg)\b|=~")
SUB = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\[[^\]]*\]\}?|\b[A-Za-z_][A-Za-z0-9_]*\[[^\]]*\]=")

def reversed_ranges(body):
    body = re.sub(r"\[:[a-z]+:\]", "", body)
    if body.startswith("^"):
        body = body[1:]
    bad, i = [], 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1] == "-":
            a, b = body[i], body[i + 2]
            if ord(b) < ord(a):
                bad.append(a + "-" + b)
            i += 3
        else:
            i += 1
    return bad

def mode_ranges(root):
    scanned = flagged = 0
    for p in paths():
        try:
            text = read_bytes(p).decode("utf-8", "replace")
        except OSError:
            continue
        scanned += 1
        hits = 0
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#") or not HOT.search(line):
                continue
            for m in BR.finditer(SUB.sub("", line)):
                bad = reversed_ranges(m.group(0)[1:-1])
                if bad:
                    out("WARN", "regex-range", "%s:%d: %s has reversed range %s"
                        % (rel(p, root), n, m.group(0), ", ".join(bad)))
                    hits += 1
                    flagged += 1
                    if hits >= 5:
                        break
            if hits >= 5:
                break
    if scanned and not flagged:
        out("OK", "regex-range", "%d script(s) scanned, no reversed bracket ranges" % scanned)

def mode_tsv2json(_root):
    rows = []
    for l in sys.stdin:
        p = l.rstrip("\n").split("\t", 3)
        if len(p) == 4:
            rows.append(dict(zip(("level", "repo", "check", "message"), p)))
    json.dump({"counts": dict(Counter(r["level"] for r in rows)), "findings": rows}, sys.stdout, indent=2)
    print()

MODES = {"py": mode_py, "json": mode_json, "sqlite": mode_sqlite,
         "ranges": mode_ranges, "tsv2json": mode_tsv2json}
MODES[sys.argv[1]](sys.argv[2] if len(sys.argv) > 2 else "")
PYEOF

have() { command -v "$1" >/dev/null 2>&1; }

setup_colors() {
  if (( COLOR )) && [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    C_R=$'\e[31m' C_G=$'\e[32m' C_Y=$'\e[33m' C_B=$'\e[36m' C_0=$'\e[0m'
  fi
}

cleanup() {
  if [[ -n ${TMPD:-} && -d $TMPD && $TMPD == */repo-audit.* ]]; then
    rm -rf -- "$TMPD"
  fi
}

say() { printf '%s\n' "$*" | tee -a "$REPORT"; }
section() { say ""; say "== $* =="; }

emit() {
  local lvl=$1 chk=$2 col=""
  shift 2
  local msg="$*"
  msg=${msg//$'\t'/ }
  msg=${msg//$'\n'/ }
  case $lvl in
    OK)   N_OK=$((N_OK + 1));     col=$C_G ;;
    INFO) N_INFO=$((N_INFO + 1)); col=$C_B ;;
    WARN) N_WARN=$((N_WARN + 1)); col=$C_Y ;;
    FAIL) N_FAIL=$((N_FAIL + 1)); col=$C_R ;;
  esac
  printf '%s\t%s\t%s\t%s\n' "$lvl" "$REPO_LABEL" "$chk" "$msg" >> "$FINDINGS"
  printf '%-4s %-14s %s\n' "$lvl" "$chk" "$msg" >> "$REPORT"
  if (( QUIET )) && [[ $lvl == OK || $lvl == INFO ]]; then return 0; fi
  printf '%s%-4s%s %-14s %s\n' "$col" "$lvl" "$C_0" "$chk" "$msg"
}
ok()   { emit OK "$@"; }
info() { emit INFO "$@"; }
warn() { emit WARN "$@"; }
fail() { emit FAIL "$@"; }

# Remaining pipeline functions and main orchestrator available in the complete script...
