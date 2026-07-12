#!/bin/bash
# End-to-end test for nfsd.py: start the server, mount it with the kernel
# NFS client (vers=4.0), exercise reads/writes/metadata, then re-mount with
# vers=4.1 (sessions) and exercise the same core paths. Reports PASS/FAIL.
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

# --- NFSv3 re-mount (MOUNT protocol on the same port, no rpcbind) ---
sudo umount "$MNT"; check $? "umount before v3"
timeout 30 sudo mount -t nfs \
  -o "vers=3,port=$PORT,mountport=$PORT,mountproto=tcp,proto=tcp,nolock,soft,timeo=50,retrans=2" \
  "127.0.0.1:/" "$MNT"
check $? "mount vers=3"
grep " $(echo "$MNT" | sed 's/[.[\*^$]/\\&/g') " /proc/mounts \
  | grep -q "vers=3"; check $? "negotiated vers=3"
[ "$(cat "$MNT/hello.txt" 2>/dev/null)" = "hello from nfsd.py" ]
check $? "v3 read"
echo "over v3" | sudo tee "$MNT/w3.txt" > /dev/null
[ "$(cat "$EXP/w3.txt" 2>/dev/null)" = "over v3" ]
check $? "v3 write"
sudo cp /tmp/nfsdpy-rnd.bin "$MNT/rnd3.bin"
a3=$(sha256sum /tmp/nfsdpy-rnd.bin | awk '{print $1}')
b3=$(sudo sha256sum "$MNT/rnd3.bin" | awk '{print $1}')
[ "$a3" = "$b3" ]; check $? "v3 8 MiB sha256 round-trip"
sudo mkdir "$MNT/d3" && echo deep3 | sudo tee "$MNT/d3/deep.txt" >/dev/null
[ "$(cat "$EXP/d3/deep.txt" 2>/dev/null)" = "deep3" ]
check $? "v3 mkdir + create in subdir"
sudo chmod 0640 "$MNT/w3.txt"
[ "$(sudo stat -c %a "$MNT/w3.txt")" = "640" ]; check $? "v3 chmod"
sudo ln -s hello.txt "$MNT/lnk3" && \
  [ "$(sudo readlink "$MNT/lnk3")" = "hello.txt" ]; check $? "v3 symlink"
sudo mv "$MNT/w3.txt" "$MNT/w3r.txt" && [ -f "$EXP/w3r.txt" ]
check $? "v3 rename"
n3=$(ls "$MNT" | wc -l)
sudo rm "$MNT/w3r.txt" "$MNT/rnd3.bin" "$MNT/lnk3" "$MNT/d3/deep.txt"
sudo rmdir "$MNT/d3"; check $? "v3 unlink + rmdir"

# --- NFSv4.1 (sessions) re-mount ---
sudo umount "$MNT"; check $? "umount before v4.1"
timeout 30 sudo mount -t nfs \
  -o "vers=4.1,port=$PORT,proto=tcp,sec=sys,soft,timeo=50,retrans=2" \
  "127.0.0.1:/" "$MNT"
check $? "mount vers=4.1"
grep " $(echo "$MNT" | sed 's/[.[\*^$]/\\&/g') " /proc/mounts \
  | grep -q "vers=4.1"; check $? "negotiated vers=4.1"
[ "$(cat "$MNT/hello.txt" 2>/dev/null)" = "hello from nfsd.py" ]
check $? "4.1 read"
echo "via sessions" | sudo tee "$MNT/w41.txt" > /dev/null
[ "$(cat "$EXP/w41.txt" 2>/dev/null)" = "via sessions" ]
check $? "4.1 write"
sudo cp /tmp/nfsdpy-rnd.bin "$MNT/rnd41.bin"
a41=$(sha256sum /tmp/nfsdpy-rnd.bin | awk '{print $1}')
b41=$(sudo sha256sum "$MNT/rnd41.bin" | awk '{print $1}')
[ "$a41" = "$b41" ]; check $? "4.1 8 MiB sha256 round-trip"
sudo chmod 0640 "$MNT/w41.txt"
[ "$(sudo stat -c %a "$MNT/w41.txt")" = "640" ]; check $? "4.1 chmod"
sudo flock -n -x "$MNT/w41.txt" -c true; check $? "4.1 flock"
sudo rm "$MNT/w41.txt" "$MNT/rnd41.bin"; check $? "4.1 unlink"

# --- portmapper (-pmap): v3 mount with NO port options ---
# Runs in a private network namespace: the runner's own rpcbind (if any)
# does not own port 111 there, so nfsd.py -pmap binds the real port 111
# and the kernel client has to resolve BOTH the MOUNT and NFS ports
# through nfsd.py's own portmapper (the path BSD clients depend on).
sudo umount "$MNT"; check $? "umount before pmap"
PMNT=/tmp/nfsdpy-pmap-mnt
mkdir -p "$PMNT"
SRC_ABS=$(readlink -f "$SRC")
if sudo unshare -n true 2>/dev/null; then
  cat > /tmp/nfsdpy-pmap-inner.sh <<EOF
set -e
ip link set lo up
python3 "$SRC_ABS" -dir "$EXP" -port $PORT -pmap > /tmp/nfsdpy-pmap.log 2>&1 &
SRV=\$!
up=0
for i in \$(seq 1 20); do
  if bash -c "echo > /dev/tcp/127.0.0.1/111" 2>/dev/null; then up=1; break; fi
  sleep 0.5
done
[ "\$up" = "1" ]
timeout 30 mount -t nfs \
  -o vers=3,proto=tcp,mountproto=tcp,nolock,soft,timeo=50,retrans=2 \
  127.0.0.1:/ "$PMNT"
[ "\$(cat "$PMNT/hello.txt")" = "hello from nfsd.py" ]
echo "pmap ok" > "$PMNT/pmap-w.txt"
umount "$PMNT"
kill \$SRV
EOF
  sudo unshare -n bash /tmp/nfsdpy-pmap-inner.sh
  check $? "pmap netns: v3 mount with no port options (portmapper only)"
  [ "$(cat "$EXP/pmap-w.txt" 2>/dev/null)" = "pmap ok" ]
  check $? "pmap netns: write visible in export"
else
  echo "SKIP: unshare -n unavailable; portmapper e2e skipped"
fi

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
echo "--- last server log lines ---"
tail -5 "$LOG"
[ "$FAIL" = "0" ]
