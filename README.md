# nfsd.py

[![test](https://github.com/anyvm-org/nfsd/actions/workflows/test.yml/badge.svg)](https://github.com/anyvm-org/nfsd/actions/workflows/test.yml)
[![pynfs 4.0](https://img.shields.io/badge/pynfs%20NFSv4.0-589%20passed%2C%200%20failed-brightgreen)](test/pynfs-known-failures.txt)
[![pynfs 4.1](https://img.shields.io/badge/pynfs%20NFSv4.1-172%2F184%20passed-brightgreen)](test/pynfs41-known-failures.txt)
[![python](https://img.shields.io/badge/python-3.8%2B%20stdlib%20only-blue)](nfsd.py)

A cross-platform, **user-space NFSv3 / NFSv4.0 / NFSv4.1 / NFSv4.2 server
in one pure-Python file**. Point it at a local directory and a TCP port,
and any NFSv3 or NFSv4.x client can mount it.

- **Standard library only.** No third-party packages, no C extensions, no
  kernel module, no FUSE. Just sockets and basic filesystem operations.
- **Single file.** Copy `nfsd.py` anywhere Python 3.8+ runs (Linux, Windows,
  macOS) and start it.
- **Spec-derived protocol tables.** Every protocol constant is
  machine-extracted from RFC 1813 (NFSv3), RFC 7531 (NFSv4.0 XDR), RFC 5662
  (NFSv4.1 XDR), RFC 7863 (NFSv4.2 XDR), RFC 1833 (portmapper) and RFC 5531
  (ONC RPC) by `tools/gen_constants.py` -- no hand-typed magic numbers.

## Usage

```sh
python3 nfsd.py -dir /path/to/export -port 2049
```

Mount from Linux (vers=4.2, vers=4.1, vers=4.0 and vers=3 all work):

```sh
sudo mount -t nfs -o vers=4.2,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x
sudo mount -t nfs -o vers=4.1,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x
sudo mount -t nfs -o vers=4.0,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x
sudo mount -t nfs \
  -o vers=3,port=2049,mountport=2049,mountproto=tcp,proto=tcp,nolock \
  HOST:/ /mnt/x
```

For NFSv3 the MOUNT protocol is served on the same TCP port, so pass
`mountport=` explicitly and no rpcbind/portmapper is needed. There is no
NLM lock manager: mount v3 with `nolock` (v4 locking is fully supported).

macOS:

```sh
sudo mount -t nfs -o vers=4,port=2049,resvport HOST:/ /Volumes/x
```

BSD v3 clients whose `mount_nfs` has no `mountport=` option (OpenBSD,
NetBSD, DragonFly) can only discover the MOUNT/NFS ports through a
portmapper on port 111. Start the server with `-pmap` and they mount with
no port options at all (TCP must be selected; these clients default their
portmapper queries to UDP, which `-pmap` also answers):

```sh
python3 nfsd.py -dir /path/to/export -pmap

mount -t nfs -o -T HOST:/ /mnt/x        # OpenBSD
mount -t nfs -o tcp HOST:/ /mnt/x       # NetBSD (TCP is its default)
mount_nfs -3 -T HOST:/ /mnt/x           # DragonFly
```

### Options

| Option      | Default   | Meaning                                    |
|-------------|-----------|--------------------------------------------|
| `-dir`      | (required)| local directory to export                  |
| `-port`     | `2049`    | TCP port to listen on                      |
| `-bind`     | `0.0.0.0` | bind address                               |
| `-ro`       | off       | export read-only                           |
| `-vers`     | all       | serve only one major version: `3` or `4` (4 = 4.0/4.1/4.2) |
| `-lease`    | `90`      | NFSv4 lease time (seconds)                 |
| `-anonuid`  | `65534`   | uid reported/used for anonymous access     |
| `-anongid`  | `65534`   | gid reported/used for anonymous access     |
| `-pmap`     | off       | also serve portmapper v2 on port 111 (tcp+udp) |
| `-pmap-port`| `111`     | portmapper port (for tests)                |
| `-v`/`-vv`  | warnings  | info / per-operation debug logging         |

No rpcbind/portmapper is needed for clients that can point at the port
directly: NFSv4 uses a single port by design, and for NFSv3 both the NFS
and MOUNT programs answer on this same port (`port=`/`mountport=`). For
v3 clients that cannot (`mountport=` is Linux-only), `-pmap` serves a
built-in portmapper v2 (RFC 1833) on port 111 whose static table points
every program at the server port. Binding port 111 needs no privileges on
Windows or macOS 10.14+; on Linux it needs root (a bind failure is logged
and the server keeps running without it).

Run the server as root if you want `chown` from clients to succeed on
POSIX (only root may change file ownership); everything else works fine
unprivileged on a port >= 1024.

## What is implemented

- ONC RPC v2 over TCP with record marking; AUTH_SYS and AUTH_NONE.
- NFSv3 (RFC 1813): all 21 procedures + NULL (GETATTR/SETATTR/LOOKUP/
  ACCESS/READLINK/READ/WRITE/CREATE incl. exclusive create/MKDIR/SYMLINK/
  MKNOD/REMOVE/RMDIR/RENAME/LINK/READDIR/READDIRPLUS/FSSTAT/FSINFO/
  PATHCONF/COMMIT) with wcc_data pre/post attributes, plus the MOUNT v3
  program (MNT/DUMP/UMNT/UMNTALL/EXPORT) dispatched on the same TCP
  port -- no rpcbind, no separate mountd.
- Portmapper v2 (RFC 1833, opt-in via `-pmap`): NULL/GETPORT/DUMP over
  TCP and UDP on port 111, answering from a static table that maps the
  NFS (v3/v4) and MOUNT programs to the server port; SET/UNSET are
  refused, CALLIT is unimplemented.
- NFSv4.0 COMPOUND with the full operation set a Linux/macOS client uses:
  SETCLIENTID(_CONFIRM), RENEW, PUTROOTFH/PUTFH/GETFH/SAVEFH/RESTOREFH,
  LOOKUP(P), ACCESS, GETATTR/SETATTR, VERIFY/NVERIFY, READDIR, READLINK,
  OPEN (UNCHECKED/GUARDED/EXCLUSIVE create), OPEN_CONFIRM, OPEN_DOWNGRADE,
  CLOSE, READ, WRITE, COMMIT, CREATE (dir/symlink/fifo), REMOVE, RENAME,
  LINK, SECINFO, LOCK/LOCKT/LOCKU (in-memory byte-range locks),
  RELEASE_LOCKOWNER.
- NFSv4.1 (RFC 5661) session support: EXCHANGE_ID with the full
  client-record state machine of sec 18.35.4 (update/collision/restart
  cases, unconfirmed-record lease expiry), CREATE_SESSION with
  exactly-once semantics and channel-attribute validation
  (TOOSMALL/INVAL), SEQUENCE with a per-slot exactly-once reply cache
  and enforcement of the negotiated limits (REQ_TOO_BIG, REP_TOO_BIG,
  REP_TOO_BIG_TO_CACHE, TOO_MANY_OPS), the current stateid
  (sec 16.2.3.1.2, incl. SAVEFH/RESTOREFH), BIND_CONN_TO_SESSION,
  DESTROY_SESSION, DESTROY_CLIENTID, RECLAIM_COMPLETE (with GRACE
  gating of pre-reclaim opens), SECINFO_NO_NAME, FREE_STATEID,
  TEST_STATEID, OPEN by CLAIM_FH and EXCLUSIVE4_1 create,
  OPEN_DELEGATE_NONE_EXT want-hint replies, and the suppattr_exclcreat
  attribute. Sessions renew the lease implicitly; 4.1 compounds ignore
  owner seqids per the spec. Fore channel only: no backchannel, so no
  delegations are ever granted (the server never sets CONN_BACK_CHAN);
  pNFS/layout ops, SSV, and RPCSEC_GSS answer NFS4ERR_NOTSUPP.
- NFSv4.2 (RFC 7862) on the same session layer. Every 4.2 feature is
  OPTIONAL, so this is the profile the local filesystem can back
  honestly: **SEEK** (sparse-file SEEK_DATA/SEEK_HOLE, with the virtual
  hole at EOF and NXIO past it), **ALLOCATE** (posix_fallocate),
  **DEALLOCATE** (real hole punching via fallocate(2) on Linux, zero-fill
  elsewhere) and **intra-server COPY** (synchronous, so no OFFLOAD
  polling). CLONE, READ_PLUS, WRITE_SAME, IO_ADVISE, inter-server COPY,
  the OFFLOAD_* ops and the 4.2 attributes (clone_blksize, sec_label,
  change_attr_type, ...) answer NFS4ERR_NOTSUPP -- which the spec allows
  for all of them, and Linux clients fall back transparently.
- Attributes: 41 fattr4 attributes incl. mode/owner/group/times/space/statfs.
- An open-file descriptor cache, so streams of READ/WRITE ops reuse one
  descriptor instead of open/close per RPC (the dominant write cost).
- Windows specifics: uid/gid/mode persisted in an NTFS Alternate Data
  Stream sidecar (`file:nfsd.meta`), positional I/O fallback (no os.pread on
  Windows), symlink-privilege probe.

Verified end to end against the Linux kernel client (see `test/e2e.sh`,
60 checks: vers=4.0 mount, read/write, 8 MiB checksum round-trip,
chmod/chown/truncate/mtime, rename incl. directory rename, symlink/
hardlink, flock contention, 300-entry readdir, statfs -- then vers=3,
vers=4.1 and vers=4.2 re-mounts exercising the same core paths, with the
4.2 leg driving the new operations through real syscalls (`fallocate`,
`fallocate -p`, `lseek(SEEK_DATA/SEEK_HOLE)`, `copy_file_range`), and a
`-pmap` leg in a private network namespace where the client mounts v3
with no port options, resolving everything through the built-in
portmapper). Loopback throughput on a dev machine: ~266 MB/s write,
~168 MB/s read -- well above gigabit line rate.

## Testing

```sh
bash test/e2e.sh            # kernel-client mount; needs linux (or WSL2),
                            # nfs-common, sudo
python3 test/rpcsmoke.py    # protocol-level smoke; no privileges needed,
                            # runs on Linux, Windows and macOS
```

`test/rpcsmoke.py` starts the server in-process and speaks raw NFSv3,
NFSv4.0, NFSv4.1 and NFSv4.2 (RPC NULL, PUTROOTFH/LOOKUP/READ/WRITE/
CREATE/SETATTR/REMOVE, the EXCHANGE_ID/CREATE_SESSION/SEQUENCE session
flow with slot replay, GRACE gating, the current stateid, minor-version
rejection, illegal opcodes, the 4.2 SEEK/ALLOCATE/DEALLOCATE/COPY ops
with their data verified on disk and NOTSUPP for the ops we decline, the
`-vers` gating, a full MOUNT3+NFS3 pass: MNT/EXPORT, v3 create/
write/read/setattr/readdirplus/rename/remove/fsinfo, portmapper v2
GETPORT/DUMP/SET over both TCP and UDP, and the wildcard fallback for a
denied specific-address bind -- simulated everywhere, and additionally
exercised against the real macOS privileged-port rule on port 111 when
running on macOS) -- this is also what CI runs on all three OSes. The
Windows-hosted server has additionally been verified end to end with a
real Linux kernel client (WSL2) including chmod/chown persistence into
the NTFS ADS sidecar.

## Protocol conformance (pynfs)

The [pynfs](https://github.com/kofemann/pynfs) servertests suites are the
acceptance harness, for both minor versions:

```sh
bash test/conformance.sh              # NFSv4.0 suite, 600+ tests
MINOR=1 bash test/conformance.sh      # NFSv4.1 suite
```

NFSv4.0 standing: **589 passed / 0 failed / 2 warned / 10 skipped of the
601 selected tests**, zero server crashes or hangs. This includes the
strict NFSv4.0 state machine: open/lock-owner seqid enforcement with the
at-most-once replay cache (BAD_SEQID), stateid generations
(OLD_STATEID/STALE_STATEID), share reservations, an RPC duplicate-request
cache, and courteous-server lease expiry (an expired client's state is
reaped when it conflicts). The 2 warnings are POSIX-advisory; the 10
skips are tests the suite itself deems inapplicable.

NFSv4.1 standing: **172 passed / 12 failed of the 184 selected tests**,
zero server crashes or hangs. Eleven of the remaining failures need real
delegations (impossible without a backchannel, see
`test/pynfs41-known-failures.txt`); the twelfth is a pynfs client-side
XDR limitation.

CI treats the per-minor-version known-failures files as baselines: any
conformance failure not listed there fails the build; a listed test that
starts passing is reported so the baseline can be tightened.

## Regenerating protocol constants

```sh
python3 tools/gen_constants.py --splice nfsd.py
```

reads the verbatim IETF documents in `spec/` (RFC 7531, 5662, 7863, 1813,
1833, 5531) and replaces the generated block in `nfsd.py`. Names shared
across specifications -- every NFSv4 minor version restates the whole XDR
-- are cross-checked for value equality during generation; a mismatch
aborts.

## Design notes

- **Inode model.** Synthetic inode numbers with a dentry map
  (`ino -> (parent, name)`); paths are rebuilt by walking parents, so a
  directory rename is O(1) and never invalidates descendant handles. Inode
  numbers are never reused.
- **File handles** are 8-byte inode numbers; all state is in-memory. After
  a server restart, old client handles return `NFS4ERR_STALE` (clients
  re-lookup on remount). There is no on-disk state database.
- **Locking** is advisory and lives in server memory: NFS clients contend
  correctly with each other, but not with local processes on the server.

## Known limitations

- NFSv3, NFSv4.0, NFSv4.1 and NFSv4.2 (no NFSv2). No delegations, no
  Kerberos (AUTH_SYS trusts client-asserted uid/gid, standard LAN model).
- NFSv3 has no NLM/NSM lock manager: mount with `nolock` (byte-range
  locking works on v4.0/4.1). NFS itself is TCP only; v3 clients either
  pass `port=`/`mountport=` explicitly or use the `-pmap` portmapper
  (which answers on TCP and UDP but only advertises TCP mappings). The
  native Windows NFS client is untested.
- NFSv4.1 runs fore channel only (no backchannel / callbacks), no pNFS,
  no SSV state protection, no session persistence.
- No cross-restart handle persistence; no grace-period reclaim.
- ACLs are not supported (mode bits only).
