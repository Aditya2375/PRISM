#!/usr/bin/env bash
# Runs the README "Clean-machine setup" steps from a fresh copy of the repository in a fresh virtualenv, and fails
# on the first step that does not do what the README says. Usage: scripts/readme_smoke.sh [python]   (default python3)
# CI runs it on every push. It binds 127.0.0.1:18443 and writes only under a temporary directory.
set -euo pipefail
PY=${1:-python3}
SRC=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'kill ${SERVER_PID:-0} 2>/dev/null || true; rm -rf "$W"' EXIT
step() { printf '\n== %s\n' "$*"; }

step "fresh copy of the repository (tracked files only)"
mkdir "$W/PRISM"
git -C "$SRC" archive HEAD | tar -x -C "$W/PRISM"
cd "$W/PRISM"

step "python -m venv .venv && pip install -r requirements.txt"
"$PY" -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt

step "python -m kig.demo"
python -m kig.demo > "$W/demo.out"
tail -n 3 "$W/demo.out"

step "init, start the API, enrol, put, get, report lost, denied, verify"
K="python -m kig.cli"; PORT=${SMOKE_PORT:-18443}; U=http://127.0.0.1:$PORT
FP=$($K init --data ./data --user asha --device asha-laptop --out asha-laptop.json | sed -n 's/^root fingerprint.*: //p')
test -n "$FP"
KIG_DATA=./data uvicorn --factory kig.server:app --host 127.0.0.1 --port "$PORT" > "$W/uvicorn.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -fs "$U/healthz" > /dev/null 2>&1 && break; sleep 0.2; done
curl -fs "$U/healthz" > /dev/null
$K keygen --user asha --device asha-phone --out asha-phone.json > phone-pub.json 2> phone-fp.txt
PF=$(sed -n 's/^fingerprint.*: //p' phone-fp.txt)
test -n "$PF"
$K enroll --url "$U" --root-fingerprint "$FP" --key asha-laptop.json --pub phone-pub.json --expect-fingerprint "$PF" --limited
echo "a line of text" > a.txt
$K put --url "$U" --root-fingerprint "$FP" --key asha-laptop.json --file-id doc --path a.txt
$K get --url "$U" --root-fingerprint "$FP" --key asha-phone.json --file-id doc --out b.txt
cmp a.txt b.txt
$K call --url "$U" --root-fingerprint "$FP" --key asha-laptop.json report_lost '{"device":"asha-phone"}'
if $K get --url "$U" --root-fingerprint "$FP" --key asha-phone.json --file-id doc --out c.txt; then
  echo "FAIL: the lost phone could still read the file"; exit 1
fi
test ! -s c.txt 2> /dev/null || { echo "FAIL: the lost phone wrote plaintext"; exit 1; }
set +e
python verifier/prism_verify.py audit --log data/audit.jsonl --pub data/server_sign.pub --anchor data/audit.head
RC=$?
set -e
test "$RC" -eq 2 || { echo "FAIL: verifier exit $RC, the README says 2 (chain verifies, no recorded head)"; exit 1; }
step "README steps OK"
