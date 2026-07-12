#!/usr/bin/env python3
"""Protocol-level smoke test for nfsd.py.

Starts the server in-process on a loopback port and speaks raw NFSv4.0
(ONC RPC + COMPOUND) to it using nfsd.py's own XDR helpers and
RFC-extracted constants. Needs no mount privileges and no kernel NFS
client, so it runs identically on Linux, Windows and macOS -- including
CI runners.

usage: python3 test/rpcsmoke.py
"""

import json
import os
import socket
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nfsd  # noqa: E402

FAILURES = []


def check(cond, label):
    if cond:
        print("PASS: %s" % label)
    else:
        print("FAIL: %s" % label)
        FAILURES.append(label)


# --- tiny raw NFSv4.0 client -------------------------------------------------

_xid = [100]


def rpc_call(sock, proc, body, cred_uid=0, cred_gid=0):
    _xid[0] += 1
    xid = _xid[0]
    pk = nfsd.Packer()
    pk.uint32(xid)
    pk.uint32(nfsd.CALL)
    pk.uint32(nfsd.RPC_VERS)
    pk.uint32(nfsd.NFS4_PROGRAM)
    pk.uint32(nfsd.NFS_V4)
    pk.uint32(proc)
    cred = nfsd.Packer()
    cred.uint32(0)                 # stamp
    cred.string("rpcsmoke")        # machinename
    cred.uint32(cred_uid)
    cred.uint32(cred_gid)
    cred.uint32(1)                 # one supplementary gid
    cred.uint32(cred_gid)
    pk.uint32(nfsd.AUTH_SYS)
    pk.opaque(cred.get())
    pk.uint32(nfsd.AUTH_NONE)
    pk.uint32(0)
    pk.raw(body)
    nfsd.write_record(sock, pk.get())
    rec = nfsd.read_record(sock)
    assert rec is not None, "connection closed"
    up = nfsd.Unpacker(rec)
    assert up.uint32() == xid, "xid mismatch"
    assert up.uint32() == nfsd.REPLY
    assert up.uint32() == nfsd.MSG_ACCEPTED, "rpc denied"
    up.uint32()
    up.opaque()                    # verifier
    astat = up.uint32()
    assert astat == nfsd.SUCCESS, "accept_stat %d" % astat
    return up


ZERO_SID = b"\0" * 16


def op_putrootfh():
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_PUTROOTFH)
    return pk.get()


def op_putfh(fh):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_PUTFH)
    pk.opaque(fh)
    return pk.get()


def op_getfh():
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_GETFH)
    return pk.get()


def op_lookup(name):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_LOOKUP)
    pk.string(name)
    return pk.get()


def op_getattr(attrs):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_GETATTR)
    pk.raw(nfsd.pack_bitmap(attrs))
    return pk.get()


def op_read(offset, count):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_READ)
    pk.raw(ZERO_SID)
    pk.uint64(offset)
    pk.uint32(count)
    return pk.get()


def op_write(offset, data):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_WRITE)
    pk.raw(ZERO_SID)
    pk.uint64(offset)
    pk.uint32(nfsd.FILE_SYNC4)
    pk.opaque(data)
    return pk.get()


def op_create_dir(name):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_CREATE)
    pk.uint32(nfsd.NF4DIR)
    pk.string(name)
    pk.uint32(0)                   # empty bitmap
    pk.opaque(b"")                 # empty attrlist
    return pk.get()


def op_setattr_mode(mode):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_SETATTR)
    pk.raw(ZERO_SID)
    pk.raw(nfsd.pack_bitmap([nfsd.FATTR4_MODE]))
    vals = nfsd.Packer()
    vals.uint32(mode)
    pk.opaque(vals.get())
    return pk.get()


def op_remove(name):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_REMOVE)
    pk.string(name)
    return pk.get()


def compound(sock, ops, minor=0, tag=b"smoke"):
    pk = nfsd.Packer()
    pk.opaque(tag)
    pk.uint32(minor)
    pk.uint32(len(ops))
    for o in ops:
        pk.raw(o)
    up = rpc_call(sock, nfsd.NFSPROC4_COMPOUND, pk.get())
    status = up.uint32()
    up.opaque()                    # tag
    n = up.uint32()
    return status, n, up


def walk_results(up, n):
    """Consume n resops, returning [(opnum, status, payload)]."""
    out = []
    for _ in range(n):
        opnum = up.uint32()
        st = up.uint32()
        payload = None
        if st == nfsd.NFS4_OK:
            if opnum == nfsd.OP_GETFH:
                payload = up.opaque()
            elif opnum == nfsd.OP_GETATTR:
                nw = up.uint32()
                for _ in range(nw):
                    up.uint32()
                payload = up.opaque()
            elif opnum == nfsd.OP_READ:
                eof = up.boolean()
                payload = (eof, up.opaque())
            elif opnum == nfsd.OP_WRITE:
                cnt = up.uint32()
                up.uint32()
                up.opaque_fixed(8)
                payload = cnt
            elif opnum in (nfsd.OP_CREATE,):
                up.boolean()
                up.uint64()
                up.uint64()
                nw = up.uint32()
                for _ in range(nw):
                    up.uint32()
            elif opnum == nfsd.OP_SETATTR:
                nw = up.uint32()
                for _ in range(nw):
                    up.uint32()
            elif opnum == nfsd.OP_REMOVE:
                up.boolean()
                up.uint64()
                up.uint64()
        elif opnum == nfsd.OP_SETATTR:
            nw = up.uint32()
            for _ in range(nw):
                up.uint32()
        out.append((opnum, st, payload))
    return out


def main():
    export = tempfile.mkdtemp(prefix="nfsdpy-smoke-")
    with open(os.path.join(export, "hello.txt"), "w") as f:
        f.write("hello smoke")

    srv_nfs = nfsd.NfsServer(export, 0)
    srv = nfsd.Server(("127.0.0.1", 0), nfsd.ConnHandler)
    srv.nfs = srv_nfs
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("server on 127.0.0.1:%d exporting %s" % (port, export))

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)

    # 1. RPC NULL ping
    rpc_call(sock, nfsd.NFSPROC4_NULL, b"")
    check(True, "RPC NULL ping")

    # 2. PUTROOTFH + GETFH + GETATTR(type)
    st, n, up = compound(sock, [op_putrootfh(), op_getfh(),
                                op_getattr([nfsd.FATTR4_TYPE])])
    res = walk_results(up, n)
    check(st == nfsd.NFS4_OK, "root compound status OK")
    root_fh = res[1][2]
    check(len(root_fh) == 8, "root filehandle is 8 bytes")
    tp = nfsd.Unpacker(res[2][2]).uint32()
    check(tp == nfsd.NF4DIR, "root type is NF4DIR")

    # 3. LOOKUP + READ with the zero (anonymous) stateid
    st, n, up = compound(sock, [op_putrootfh(), op_lookup("hello.txt"),
                                op_read(0, 100)])
    res = walk_results(up, n)
    check(st == nfsd.NFS4_OK, "lookup+read status OK")
    eof, data = res[2][2]
    check(data == b"hello smoke" and eof, "read returns file content + eof")

    # 4. WRITE via zero stateid, verify on disk
    st, n, up = compound(sock, [op_putrootfh(), op_lookup("hello.txt"),
                                op_write(0, b"WRITTEN over rpc")])
    res = walk_results(up, n)
    check(st == nfsd.NFS4_OK and res[2][2] == 16, "write 16 bytes OK")
    with open(os.path.join(export, "hello.txt"), "rb") as f:
        check(f.read() == b"WRITTEN over rpc", "write visible on disk")

    # 5. CREATE directory
    st, n, up = compound(sock, [op_putrootfh(), op_create_dir("subdir")])
    walk_results(up, n)
    check(st == nfsd.NFS4_OK and os.path.isdir(os.path.join(export, "subdir")),
          "mkdir via CREATE")

    # 6. SETATTR mode 0640
    st, n, up = compound(sock, [op_putrootfh(), op_lookup("hello.txt"),
                                op_setattr_mode(0o640)])
    walk_results(up, n)
    check(st == nfsd.NFS4_OK, "setattr mode status OK")
    if os.name == "nt":
        with open(os.path.join(export, "hello.txt") + nfsd.SIDE_STREAM) as f:
            side = json.load(f)
        check(side.get("mode") == 0o640, "mode persisted in ADS sidecar")
    else:
        import stat as statmod
        m = statmod.S_IMODE(os.stat(os.path.join(export, "hello.txt")).st_mode)
        check(m == 0o640, "mode applied on disk (got %o)" % m)

    # 7. REMOVE the directory
    st, n, up = compound(sock, [op_putrootfh(), op_remove("subdir")])
    walk_results(up, n)
    check(st == nfsd.NFS4_OK
          and not os.path.exists(os.path.join(export, "subdir")),
          "REMOVE directory")

    # 8. minorversion 1 must be rejected with an empty resarray
    st, n, up = compound(sock, [op_putrootfh()], minor=1)
    check(st == nfsd.NFS4ERR_MINOR_VERS_MISMATCH and n == 0,
          "minorversion 1 rejected")

    # 9. unknown opcode -> OP_ILLEGAL
    bad = nfsd.Packer()
    bad.uint32(9999)
    st, n, up = compound(sock, [op_putrootfh(), bad.get()])
    check(st == nfsd.NFS4ERR_OP_ILLEGAL, "unknown opcode -> OP_ILLEGAL")

    sock.close()
    srv.shutdown()
    srv.server_close()
    srv_nfs.cache.close_all()

    print()
    if FAILURES:
        print("RESULT: %d FAILURES: %s" % (len(FAILURES), FAILURES))
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
