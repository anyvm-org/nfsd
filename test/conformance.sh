#!/bin/bash
# pynfs NFSv4.0 conformance run with a known-failures baseline.
#
# Runs the pynfs servertests suite against nfsd.py and compares the set of
# failing test codes with test/pynfs-known-failures.txt:
#   - a failure NOT in the baseline is a REGRESSION -> exit 1
#   - a baseline entry that now passes is reported (tighten the baseline)
#
# usage: bash test/conformance.sh [port]
# env:   PYNFS_DIR (default /tmp/pynfs) - pynfs checkout, cloned if missing
#        REPO      (default: parent of this script) - nfsd-py checkout
set +e
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${REPO:-$(dirname "$HERE")}
PORT=${1:-12061}
PYNFS_DIR=${PYNFS_DIR:-/tmp/pynfs}
BASELINE="$REPO/test/pynfs-known-failures.txt"
OUT=/tmp/pynfs-conformance.txt
LOG=/tmp/nfsdpy-conformance.log

# --- get and build pynfs ---
if [ ! -d "$PYNFS_DIR" ]; then
  git clone --depth 1 https://github.com/kofemann/pynfs "$PYNFS_DIR" || exit 1
fi
if [ ! -d "$PYNFS_DIR/nfs4.0/xdrdef" ] && [ ! -f "$PYNFS_DIR/nfs4.0/nfs4_const.py" ]; then
  (cd "$PYNFS_DIR" && python3 setup.py build > /dev/null 2>&1)
fi

# --- start server ---
EXP=$(mktemp -d /tmp/nfsdpy-conf.XXXXXX)
chmod 777 "$EXP"
sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
sleep 0.3
(sudo python3 "$REPO/nfsd.py" -dir "$EXP" -port "$PORT" -bind 127.0.0.1 \
  > "$LOG" 2>&1 &)
up=0
for i in $(seq 1 20); do
  bash -c "echo > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null && { up=1; break; }
  sleep 0.5
done
[ "$up" = "1" ] || { echo "FATAL: server did not start"; tail -20 "$LOG"; exit 1; }

# --- run the suite ---
cd "$PYNFS_DIR/nfs4.0" || exit 1
timeout 2400 python3 -u testserver.py "127.0.0.1:$PORT/" \
  --maketree --rundeps --hidepass all > "$OUT" 2>&1
rc=$?
sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
if [ "$rc" != "0" ]; then
  echo "FATAL: testserver exited rc=$rc"
  tail -30 "$OUT"
  exit 1
fi

echo "=== pynfs summary ==="
tail -3 "$OUT"

# --- compare failures against the baseline ---
ACTUAL=$(grep -E ': FAILURE' "$OUT" | awk '{print $1}' | sort -u)
KNOWN=$(grep -vE '^\s*(#|$)' "$BASELINE" 2>/dev/null | awk '{print $1}' | sort -u)

NEW=$(comm -23 <(echo "$ACTUAL") <(echo "$KNOWN"))
FIXED=$(comm -13 <(echo "$ACTUAL") <(echo "$KNOWN"))

if [ -n "$FIXED" ]; then
  echo "--- NOTE: baseline entries that now PASS (tighten the baseline): ---"
  echo "$FIXED" | tr '\n' ' '; echo
fi

PASSED=$(grep -oE '[0-9]+ Passed' "$OUT" | awk '{print $1}')
if [ -z "$PASSED" ] || [ "$PASSED" -lt 400 ]; then
  echo "FATAL: implausible pass count '$PASSED' (suite broken?)"
  exit 1
fi

if [ -n "$NEW" ]; then
  echo "=== REGRESSION: new conformance failures not in baseline: ==="
  echo "$NEW" | tr '\n' ' '; echo
  echo "--- details ---"
  for code in $NEW; do
    grep -A3 "^$code " "$OUT" | head -5
  done
  exit 1
fi

echo "=== conformance OK: no new failures ($PASSED passed) ==="
exit 0
