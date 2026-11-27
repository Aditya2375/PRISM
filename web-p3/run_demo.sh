#!/usr/bin/env bash
# Start everything for the screen recording: the PRISM service, the local user backend, and this web app,
# with demo data (Asha the admin, her limited phone, Ravi, three files, a lost phone and the alerts it causes).
# Usage, from the repository root, with the Python requirements installed:  bash web-p3/run_demo.sh
# Opens nothing by itself. It prints the address and the two tokens, and stops everything on Ctrl-C.
# Data goes to a fresh directory under /tmp. The tokens are printed to this terminal only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="${PRISM_DEMO_DIR:-$(mktemp -d /tmp/prism-demo.XXXXXX)}"
export PYTHONPATH="$ROOT"
K="python -m kig.cli"; U=http://127.0.0.1:8443; WEB=4173
pids=(); cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }; trap cleanup EXIT INT TERM
cd "$ROOT/web-p3"; [ -d node_modules ] || npm ci --no-audit --no-fund; [ -d dist ] || npm run build
cd "$D"
FP=$($K init --data ./data --user asha --device asha-laptop --out asha-laptop.json | sed -n 's/^root fingerprint.*: //p')
KIG_DATA="$D/data" KIG_CORS_ORIGINS="http://localhost:$WEB" uvicorn --factory kig.server:app --host 127.0.0.1 --port 8443 >svc.log 2>&1 & pids+=($!)
for _ in $(seq 40); do curl -sf $U/healthz >/dev/null && break; sleep 0.25; done
R="--root-fingerprint $FP"
$K keygen --user asha --device asha-phone --out asha-phone.json > phone-pub.json 2> phone.err
$K enroll --url $U $R --key asha-laptop.json --pub phone-pub.json --expect-fingerprint "$(sed -n 's/^fingerprint.*: //p' phone.err)" --limited >/dev/null
$K call --url $U $R --key asha-laptop.json create_user '{"user":"ravi","role":"member"}' >/dev/null
$K keygen --user ravi --device ravi-laptop --out ravi-laptop.json > ravi-pub.json 2> ravi.err
$K enroll --url $U $R --key asha-laptop.json --pub ravi-pub.json --expect-fingerprint "$(sed -n 's/^fingerprint.*: //p' ravi.err)" >/dev/null
echo "payroll for 2026" > a.txt; echo "launch plan" > b.txt; echo "ravi private note" > c.txt
$K put --url $U $R --key asha-laptop.json --file-id payroll-2026 --path a.txt --acl ravi >/dev/null
$K put --url $U $R --key asha-laptop.json --file-id launch-plan --path b.txt >/dev/null
$K put --url $U $R --key ravi-laptop.json --file-id ravi-note --path c.txt >/dev/null
$K get --url $U $R --key asha-phone.json --file-id payroll-2026 --out p.out >/dev/null
$K call --url $U $R --key asha-laptop.json report_lost '{"device":"asha-phone","reason":"left in a taxi"}' >/dev/null
$K get --url $U $R --key asha-phone.json --file-id payroll-2026 --out p.out >/dev/null 2>&1 || true
$K get --url $U $R --key ravi-laptop.json --file-id payroll-2026 --out r.out >/dev/null
(cd "$ROOT/web-p3" && npx vite preview --port $WEB --strictPort --bypass-lock >"$D/web.log" 2>&1) & pids+=($!)
KIG_CORS_ORIGINS="http://localhost:$WEB" python -m kig.webapi --key asha-laptop.json --url $U $R --port 8788 >wa.log 2>&1 & pids+=($!)
sleep 3
echo
echo "Open:            http://localhost:$WEB"
echo "Operator token:  $(cat data/operator.token)"
echo "Session token:   $(grep -oE 'token \(send as x-prism-session\): .*' wa.log | sed 's/.*: //')   (for Device holder, signed in as asha)"
echo "Demo data in:    $D"
[ "${1:-}" = "--once" ] && exit 0
wait
