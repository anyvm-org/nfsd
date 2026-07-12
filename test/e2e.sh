#!/bin/bash
# End-to-end test for nfsd.py: start the server, mount it with the kernel
# NFS client (vers=4.0), exercise reads/writes/metadata, report PASS/FAIL.
# Needs: linux (or WSL2), python3, nfs-common, passwordless sudo.
#
# usage: bash test/e2e.sh [path-to-nfsd.py] [port]
set +e
SRC=${1:-$(dirname "$0")/../nfsd.py}
PORT=${2:-12049}
LOG=/tmp/nfsdpy-$PORT.log
EXP=$(mktemp -d /tmp/nfsdpy-exp.XXXXXX)
MNT=$(mktemp -d /tmp/nfsdpy-mnt.XXXXXX)
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $*"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

cleanup() {
  sudo umount -f "$MNT" 2>/dev/null
  sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
}
trap cleanup EXIT

# --- seed export ---
echo "hello from nfsd.py" > "$EXP/hello.txt"
mkdir "$EXP/sub"
echo "nested" > "$EXP/sub/nested.txt"

# --- start server ---
# Run the server as root so that chown/chmod-any-owner semantics can be
# exercised end to end (an unprivileged server correctly returns EPERM
# for chown, which is also fine in real deployments).
sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
sleep 0.3
(sudo python3 "$SRC" -dir "$EXP" -port "$PORT" -bind 127.0.0.1 -vv > "$LOG" 2>&1 &)
up=0
for i in $(seq 1 20); do
  if bash -c "echo > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then up=1; break; fi
  sleep 0.5
done
if [ "$up" != "1" ]; then
  echo "FATAL: server did not start"; tail -30 "$LOG"; exit 1
fi
echo "server up on port $PORT (export $EXP)"

# --- mount ---
timeout 30 sudo mount -t nfs \
  -o "vers=4.0,port=$PORT,proto=tcp,sec=sys,soft,timeo=50,retrans=2" \
  "127.0.0.1:/" "$MNT"
if [ "$?" != "0" ]; then
  echo "FATAL: mount failed"; tail -40 "$LOG"; exit 1
fi
ok "mount vers=4.0"

# --- read tests ---
c=$(cat "$MNT/hello.txt" 2>/dev/null)
[ "$c" = "hello from nfsd.py" ]; check $? "read pre-existing file"
c=$(cat "$MNT/sub/nested.txt" 2>/dev/null)
[ "$c" = "nested" ]; check $? "read nested file"
n=$(ls "$MNT" | wc -l)
[ "$n" = "2" ]; check $? "readdir count ($n)"
sudo stat "$MNT/hello.txt" > /dev/null; check $? "stat"

# --- write tests ---
echo "written over nfs" | sudo tee "$MNT/w.txt" > /dev/null
[ "$(cat "$EXP/w.txt" 2>/dev/null)" = "written over nfs" ]
check $? "write lands in export dir"

echo "appended" | sudo tee -a "$MNT/w.txt" > /dev/null
[ "$(tail -1 "$EXP/w.txt" 2>/dev/null)" = "appended" ]; check $? "append"

sudo mkdir "$MNT/newdir" && [ -d "$EXP/newdir" ]; check $? "mkdir"
echo deep | sudo tee "$MNT/newdir/deep.txt" > /dev/null
[ -f "$EXP/newdir/deep.txt" ]; check $? "create in subdir"

# --- 8 MiB integrity round-trip ---
head -c 8388608 /dev/urandom > /tmp/nfsdpy-rnd.bin
sudo cp /tmp/nfsdpy-rnd.bin "$MNT/rnd.bin"
a=$(sha256sum /tmp/nfsdpy-rnd.bin | awk '{print $1}')
b=$(sudo sha256sum "$MNT/rnd.bin" | awk '{print $1}')
c2=$(sha256sum "$EXP/rnd.bin" | awk '{print $1}')
[ "$a" = "$b" ] && [ "$a" = "$c2" ]; check $? "8 MiB sha256 round-trip"

# --- metadata ---
sudo chmod 0640 "$MNT/w.txt"
[ "$(sudo stat -c %a "$MNT/w.txt")" = "640" ]; check $? "chmod 0640"
sudo chown 1234:5678 "$MNT/w.txt" 2>/dev/null
[ "$(sudo stat -c '%u:%g' "$MNT/w.txt")" = "1234:5678" ]; check $? "chown 1234:5678"
sudo truncate -s 5 "$MNT/w.txt"
[ "$(sudo stat -c %s "$MNT/w.txt")" = "5" ]; check $? "truncate to 5"
sudo touch -d "2020-01-02 03:04:05 UTC" "$MNT/w.txt"
[ "$(sudo stat -c %Y "$MNT/w.txt")" = "1577934245" ]; check $? "set mtime"

# --- rename / remove ---
sudo mv "$MNT/w.txt" "$MNT/renamed.txt" && [ -f "$EXP/renamed.txt" ]
check $? "rename within dir"
echo A | sudo tee "$MNT/a.txt" >/dev/null
echo B | sudo tee "$MNT/newdir/b.txt" >/dev/null
sudo mv -f "$MNT/a.txt" "$MNT/newdir/b.txt"
[ "$(cat "$EXP/newdir/b.txt")" = "A" ]; check $? "rename over existing"
sudo mv "$MNT/newdir" "$MNT/renamedir"
[ "$(cat "$MNT/renamedir/deep.txt" 2>/dev/null)" = "deep" ]
check $? "directory rename keeps children reachable"
sudo rm "$MNT/renamed.txt" && [ ! -e "$EXP/renamed.txt" ]; check $? "unlink"
sudo rm "$MNT/renamedir/deep.txt" "$MNT/renamedir/b.txt"
sudo rmdir "$MNT/renamedir" && [ ! -e "$EXP/renamedir" ]; check $? "rmdir"

# --- symlink ---
sudo ln -s hello.txt "$MNT/lnk"
t=$(sudo readlink "$MNT/lnk" 2>/dev/null)
[ "$t" = "hello.txt" ]; check $? "symlink + readlink"
[ "$(sudo cat "$MNT/lnk" 2>/dev/null)" = "hello from nfsd.py" ]
check $? "read through symlink"

# --- hardlink ---
sudo ln "$MNT/hello.txt" "$MNT/hardlnk" 2>/dev/null
n=$(sudo stat -c %h "$MNT/hardlnk" 2>/dev/null)
[ "$n" = "2" ]; check $? "hardlink nlink=2"

# --- locking ---
sudo touch "$MNT/lockfile"
sudo flock -x "$MNT/lockfile" -c "sleep 2" &
sleep 0.6
sudo flock -n -x "$MNT/lockfile" -c true 2>/dev/null
[ "$?" != "0" ]; check $? "flock contention blocked"
wait
sudo flock -n -x "$MNT/lockfile" -c true
check $? "flock acquired after release"

# --- big directory ---
sudo bash -c "cd '$MNT'; mkdir bigdir; for i in \$(seq 1 300); do : > bigdir/f\$i; done"
n=$(ls "$MNT/bigdir" | wc -l)
[ "$n" = "300" ]; check $? "readdir 300 entries ($n)"

# --- df ---
sudo df "$MNT" > /dev/null; check $? "statfs (df)"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
echo "--- last server log lines ---"
tail -5 "$LOG"
[ "$FAIL" = "0" ]
