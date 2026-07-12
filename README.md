# nfsd.py

A cross-platform, **user-space NFSv4.0 server in one pure-Python file**.
Point it at a local directory and a TCP port, and any NFSv4.0 client can
mount it.

- **Standard library only.** No third-party packages, no C extensions, no
  kernel module, no FUSE. Just sockets and basic filesystem operations.
- **Single file.** Copy `nfsd.py` anywhere Python 3.8+ runs (Linux, Windows,
  macOS) and start it.
- **Spec-derived protocol tables.** Every protocol constant is
  machine-extracted from RFC 7531 (NFSv4.0 XDR) and RFC 5531 (ONC RPC) by
  `tools/gen_constants.py` -- no hand-typed magic numbers.

## Usage

```sh
python3 nfsd.py -dir /path/to/export -port 2049
```

Mount from Linux:

```sh
sudo mount -t nfs -o vers=4.0,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x
```

macOS:

```sh
sudo mount -t nfs -o vers=4,port=2049,resvport HOST:/ /Volumes/x
```

### Options

| Option      | Default   | Meaning                                    |
|-------------|-----------|--------------------------------------------|
| `-dir`      | (required)| local directory to export                  |
| `-port`     | `2049`    | TCP port to listen on                      |
| `-bind`     | `0.0.0.0` | bind address                               |
| `-ro`       | off       | export read-only                           |
| `-lease`    | `90`      | NFSv4 lease time (seconds)                 |
| `-anonuid`  | `65534`   | uid reported/used for anonymous access     |
| `-anongid`  | `65534`   | gid reported/used for anonymous access     |
| `-v`/`-vv`  | warnings  | info / per-operation debug logging         |

No rpcbind/portmapper is needed: NFSv4 uses a single port and clients pass
`port=` explicitly.

Run the server as root if you want `chown` from clients to succeed on
POSIX (only root may change file ownership); everything else works fine
unprivileged on a port >= 1024.

## What is implemented

- ONC RPC v2 over TCP with record marking; AUTH_SYS and AUTH_NONE.
- NFSv4.0 COMPOUND with the full operation set a Linux/macOS client uses:
  SETCLIENTID(_CONFIRM), RENEW, PUTROOTFH/PUTFH/GETFH/SAVEFH/RESTOREFH,
  LOOKUP(P), ACCESS, GETATTR/SETATTR, VERIFY/NVERIFY, READDIR, READLINK,
  OPEN (UNCHECKED/GUARDED/EXCLUSIVE create), OPEN_CONFIRM, OPEN_DOWNGRADE,
  CLOSE, READ, WRITE, COMMIT, CREATE (dir/symlink/fifo), REMOVE, RENAME,
  LINK, SECINFO, LOCK/LOCKT/LOCKU (in-memory byte-range locks),
  RELEASE_LOCKOWNER.
- Attributes: 41 fattr4 attributes incl. mode/owner/group/times/space/statfs.
- An open-file descriptor cache, so streams of READ/WRITE ops reuse one
  descriptor instead of open/close per RPC (the dominant write cost).
- Windows specifics: uid/gid/mode persisted in an NTFS Alternate Data
  Stream sidecar (`file:nfsd.meta`), positional I/O fallback (no os.pread on
  Windows), symlink-privilege probe.

Verified end to end against the Linux kernel client (see `test/e2e.sh`,
26 checks: mount, read/write, 8 MiB checksum round-trip, chmod/chown/
truncate/mtime, rename incl. directory rename, symlink/hardlink, flock
contention, 300-entry readdir, statfs). Loopback throughput on a dev
machine: ~266 MB/s write, ~168 MB/s read -- well above gigabit line rate.

## Testing

```sh
bash test/e2e.sh            # kernel-client mount; needs linux (or WSL2),
                            # nfs-common, sudo
python3 test/rpcsmoke.py    # protocol-level smoke; no privileges needed,
                            # runs on Linux, Windows and macOS
```

`test/rpcsmoke.py` starts the server in-process and speaks raw NFSv4.0
(RPC NULL, PUTROOTFH/LOOKUP/READ/WRITE/CREATE/SETATTR/REMOVE, minor-version
rejection, illegal opcodes) -- this is also what CI runs on all three OSes.
The Windows-hosted server has additionally been verified end to end with a
real Linux kernel client (WSL2) including chmod/chown persistence into the
NTFS ADS sidecar.

## Regenerating protocol constants

```sh
python3 tools/gen_constants.py --splice nfsd.py
```

reads `spec/rfc7531.txt` / `spec/rfc5531.txt` (verbatim IETF documents,
included) and replaces the generated block in `nfsd.py`.

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

- NFSv4.0 only (minorversion 0). No NFSv3 (so the native Windows NFS
  *client* cannot mount this; it is v2/v3 only). No delegations, no
  Kerberos (AUTH_SYS trusts client-asserted uid/gid, standard LAN model).
- No cross-restart handle persistence; no grace-period reclaim.
- Open-owner seqid replay detection is not implemented (fine over TCP).
- ACLs are not supported (mode bits only).
