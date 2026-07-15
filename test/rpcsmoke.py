#!/usr/bin/env python3
"""Protocol-level smoke test for nfsd.py.

Starts the server in-process on a loopback port and speaks raw NFSv4.0
and NFSv4.1 (ONC RPC + COMPOUND) to it using nfsd.py's own XDR helpers
and RFC-extracted constants. Needs no mount privileges and no kernel NFS
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


def rpc_call(sock, proc, body, cred_uid=0, cred_gid=0, prog=None, vers=None,
             accept=None):
    _xid[0] += 1
    xid = _xid[0]
    pk = nfsd.Packer()
    pk.uint32(xid)
    pk.uint32(nfsd.CALL)
    pk.uint32(nfsd.RPC_VERS)
    pk.uint32(nfsd.NFS4_PROGRAM if prog is None else prog)
    pk.uint32(nfsd.NFS_V4 if vers is None else vers)
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
    want = nfsd.SUCCESS if accept is None else accept
    assert astat == want, "accept_stat %d (wanted %d)" % (astat, want)
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


# --- NFSv4.1 op builders (arg layouts per RFC 5662 XDR) ----------------------

def op_exchange_id(verifier, ownerid):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_EXCHANGE_ID)
    pk.opaque_fixed(verifier)          # co_verifier
    pk.opaque(ownerid)                 # co_ownerid
    pk.uint32(0)                       # eia_flags
    pk.uint32(nfsd.SP4_NONE)           # eia_state_protect
    pk.uint32(0)                       # eia_client_impl_id<1>: none
    return pk.get()


def _chan_attrs(pk):
    pk.uint32(0)                       # ca_headerpadsize
    pk.uint32(1049620)                 # ca_maxrequestsize
    pk.uint32(1049620)                 # ca_maxresponsesize
    pk.uint32(4096)                    # ca_maxresponsesize_cached
    pk.uint32(8)                       # ca_maxoperations
    pk.uint32(16)                      # ca_maxrequests
    pk.uint32(0)                       # ca_rdma_ird<1>: none


def op_create_session(clientid, seq):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_CREATE_SESSION)
    pk.uint64(clientid)
    pk.uint32(seq)
    pk.uint32(0)                       # csa_flags
    _chan_attrs(pk)                    # fore channel
    _chan_attrs(pk)                    # back channel
    pk.uint32(0x40000000)              # csa_cb_program
    pk.uint32(1)                       # csa_sec_parms<>: one AUTH_NONE
    pk.uint32(nfsd.AUTH_NONE)
    return pk.get()


def op_sequence(sessionid, seq, slot):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_SEQUENCE)
    pk.opaque_fixed(sessionid)
    pk.uint32(seq)
    pk.uint32(slot)
    pk.uint32(slot)                    # sa_highest_slotid
    pk.boolean(False)                  # sa_cachethis
    return pk.get()


def skip_sequence_res(up):
    up.uint32()                        # opnum
    up.uint32()                        # status
    up.opaque_fixed(nfsd.NFS4_SESSIONID_SIZE)
    for _ in range(5):
        up.uint32()                    # seqid/slot/highest/target/flags


def op_open41_create(name):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_OPEN)
    pk.uint32(0)                       # seqid (ignored in 4.1)
    pk.uint32(nfsd.OPEN4_SHARE_ACCESS_BOTH)
    pk.uint32(nfsd.OPEN4_SHARE_DENY_NONE)
    pk.uint64(0)                       # owner clientid (ignored in 4.1)
    pk.opaque(b"smoke41-owner")
    pk.uint32(nfsd.OPEN4_CREATE)
    pk.uint32(nfsd.UNCHECKED4)
    pk.uint32(0)                       # empty createattrs bitmap
    pk.opaque(b"")
    pk.uint32(nfsd.CLAIM_NULL)
    pk.string(name)
    return pk.get()


def op_write41(sid, offset, data):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_WRITE)
    pk.raw(sid)
    pk.uint64(offset)
    pk.uint32(nfsd.FILE_SYNC4)
    pk.opaque(data)
    return pk.get()


def op_close41(sid):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_CLOSE)
    pk.uint32(0)                       # seqid (ignored in 4.1)
    pk.raw(sid)
    return pk.get()


def op_reclaim_complete():
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_RECLAIM_COMPLETE)
    pk.boolean(False)                  # rca_one_fs
    return pk.get()


def op_secinfo_no_name():
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_SECINFO_NO_NAME)
    pk.uint32(nfsd.SECINFO_STYLE4_CURRENT_FH)
    return pk.get()


def op_destroy_session(sessionid):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_DESTROY_SESSION)
    pk.opaque_fixed(sessionid)
    return pk.get()


def op_destroy_clientid(clientid):
    pk = nfsd.Packer()
    pk.uint32(nfsd.OP_DESTROY_CLIENTID)
    pk.uint64(clientid)
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

    srv = nfsd.Server(("127.0.0.1", 0), nfsd.ConnHandler)
    port = srv.server_address[1]
    # created after the bind so the portmapper table advertises the real port
    srv_nfs = nfsd.NfsServer(export, port)
    srv.nfs = srv_nfs
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

    # 8. minorversion 3 must be rejected with an empty resarray
    st, n, up = compound(sock, [op_putrootfh()], minor=3)
    check(st == nfsd.NFS4ERR_MINOR_VERS_MISMATCH and n == 0,
          "minorversion 3 rejected")

    # 9. unknown opcode -> OP_ILLEGAL
    bad = nfsd.Packer()
    bad.uint32(9999)
    st, n, up = compound(sock, [op_putrootfh(), bad.get()])
    check(st == nfsd.NFS4ERR_OP_ILLEGAL, "unknown opcode -> OP_ILLEGAL")

    # --- NFSv4.1 (sessions) ---------------------------------------------

    # 10. a 4.1 compound not starting with SEQUENCE -> OP_NOT_IN_SESSION
    st, n, up = compound(sock, [op_putrootfh()], minor=1)
    check(st == nfsd.NFS4ERR_OP_NOT_IN_SESSION,
          "4.1 first op not SEQUENCE -> OP_NOT_IN_SESSION")

    # 11. EXCHANGE_ID
    st, n, up = compound(sock, [op_exchange_id(b"\x01" * 8, b"smoke41")],
                         minor=1)
    check(st == nfsd.NFS4_OK, "EXCHANGE_ID status OK")
    up.uint32()                        # opnum
    up.uint32()                        # status
    clientid = up.uint64()
    eir_seq = up.uint32()
    eir_flags = up.uint32()
    check(up.uint32() == nfsd.SP4_NONE, "EXCHANGE_ID state_protect SP4_NONE")
    up.uint64()                        # so_minor_id
    up.opaque()                        # so_major_id
    up.opaque()                        # eir_server_scope
    check(up.uint32() == 0, "EXCHANGE_ID no server_impl_id")
    check(eir_flags & nfsd.EXCHGID4_FLAG_USE_NON_PNFS != 0,
          "EXCHANGE_ID advertises non-pNFS")

    # 12. EXCHANGE_ID must be the only op of a sessionless compound
    st, n, up = compound(sock, [op_exchange_id(b"\x01" * 8, b"smoke41"),
                                op_putrootfh()], minor=1)
    check(st == nfsd.NFS4ERR_NOT_ONLY_OP,
          "EXCHANGE_ID + more ops -> NOT_ONLY_OP")

    # 13. CREATE_SESSION
    st, n, up = compound(sock, [op_create_session(clientid, eir_seq)],
                         minor=1)
    check(st == nfsd.NFS4_OK, "CREATE_SESSION status OK")
    up.uint32()                        # opnum
    up.uint32()                        # status
    sessionid = up.opaque_fixed(nfsd.NFS4_SESSIONID_SIZE)
    check(up.uint32() == eir_seq, "CREATE_SESSION echoes csa_sequence")
    csr_flags = up.uint32()
    check(csr_flags & nfsd.CREATE_SESSION4_FLAG_CONN_BACK_CHAN == 0,
          "CREATE_SESSION grants no backchannel")
    fore = [up.uint32() for _ in range(6)]
    check(up.uint32() == 0, "fore channel rdma_ird empty")
    nslots = fore[5]
    check(1 <= nslots <= 64, "fore channel slot count sane")

    # 14. an OPEN before RECLAIM_COMPLETE must be rejected with GRACE
    #     (RFC 5661 sec 18.51.3), then RECLAIM_COMPLETE clears the way
    st, n, up = compound(sock, [op_sequence(sessionid, 1, 0),
                                op_putrootfh(),
                                op_open41_create("early.txt")], minor=1)
    check(st == nfsd.NFS4ERR_GRACE, "OPEN before RECLAIM_COMPLETE -> GRACE")
    st, n, up = compound(sock, [op_sequence(sessionid, 2, 0),
                                op_reclaim_complete()], minor=1)
    check(st == nfsd.NFS4_OK, "RECLAIM_COMPLETE OK")

    # 15. SEQUENCE + PUTROOTFH + GETFH
    st, n, up = compound(sock, [op_sequence(sessionid, 3, 0),
                                op_putrootfh(), op_getfh()], minor=1)
    check(st == nfsd.NFS4_OK, "SEQUENCE compound status OK")
    reply1 = bytes(up.data[up.pos:])
    up.uint32()                        # opnum SEQUENCE
    up.uint32()                        # status
    check(up.opaque_fixed(nfsd.NFS4_SESSIONID_SIZE) == sessionid,
          "SEQUENCE echoes sessionid")
    check(up.uint32() == 3, "SEQUENCE echoes seqid")
    check(up.uint32() == 0, "SEQUENCE echoes slotid")

    # 16. retransmission on the same slot/seqid replays the cached reply
    st, n, up = compound(sock, [op_sequence(sessionid, 3, 0),
                                op_putrootfh(), op_getfh()], minor=1)
    reply2 = bytes(up.data[up.pos:])
    check(reply1 == reply2, "same-slot retransmit replays cached reply")

    # 17. mid-compound SEQUENCE -> SEQUENCE_POS
    st, n, up = compound(sock, [op_sequence(sessionid, 4, 0),
                                op_sequence(sessionid, 5, 1)], minor=1)
    check(st == nfsd.NFS4ERR_SEQUENCE_POS,
          "second SEQUENCE in compound -> SEQUENCE_POS")

    # 18. OPEN(create) via 4.1: no CONFIRM rflag, WRITE with its stateid
    st, n, up = compound(sock, [op_sequence(sessionid, 5, 0),
                                op_putrootfh(),
                                op_open41_create("file41.txt")], minor=1)
    check(st == nfsd.NFS4_OK, "4.1 OPEN create status OK")
    skip_sequence_res(up)
    up.uint32(); up.uint32()           # PUTROOTFH opnum, status
    up.uint32(); up.uint32()           # OPEN opnum, status
    open_sid = up.opaque_fixed(16)     # stateid (seqid + other)
    up.boolean(); up.uint64(); up.uint64()   # change_info4
    rflags = up.uint32()
    check(rflags & nfsd.OPEN4_RESULT_CONFIRM == 0,
          "4.1 OPEN does not demand OPEN_CONFIRM")
    nw = up.uint32()
    for _ in range(nw):
        up.uint32()                    # attrset bitmap words
    check(up.uint32() == nfsd.OPEN_DELEGATE_NONE, "4.1 OPEN no delegation")

    st, n, up = compound(sock, [op_sequence(sessionid, 6, 0),
                                op_putrootfh(), op_lookup("file41.txt"),
                                op_write41(open_sid, 0, b"v41 data")],
                         minor=1)
    check(st == nfsd.NFS4_OK, "4.1 WRITE with open stateid OK")
    with open(os.path.join(export, "file41.txt"), "rb") as f:
        check(f.read() == b"v41 data", "4.1 write visible on disk")

    # close via the CURRENT stateid special value (RFC 5661 sec 16.2.3.1.2):
    # re-OPEN sets the current stateid, CLOSE(1, 0) consumes it
    st, n, up = compound(sock, [op_sequence(sessionid, 7, 0),
                                op_putrootfh(),
                                op_open41_create("file41.txt"),
                                op_close41(b"\x00\x00\x00\x01" + b"\x00" * 12)],
                         minor=1)
    check(st == nfsd.NFS4_OK, "4.1 CLOSE via current stateid OK")

    # 19. a second RECLAIM_COMPLETE -> COMPLETE_ALREADY
    st, n, up = compound(sock, [op_sequence(sessionid, 8, 0),
                                op_reclaim_complete()], minor=1)
    check(st == nfsd.NFS4ERR_COMPLETE_ALREADY,
          "second RECLAIM_COMPLETE -> COMPLETE_ALREADY")

    # 20. SECINFO_NO_NAME consumes the current filehandle
    st, n, up = compound(sock, [op_sequence(sessionid, 9, 0),
                                op_putrootfh(), op_secinfo_no_name(),
                                op_getfh()], minor=1)
    check(st == nfsd.NFS4ERR_NOFILEHANDLE and n == 4,
          "SECINFO_NO_NAME consumes the filehandle")

    # 21. DESTROY_SESSION, then SEQUENCE on it -> BADSESSION
    st, n, up = compound(sock, [op_destroy_session(sessionid)], minor=1)
    check(st == nfsd.NFS4_OK, "DESTROY_SESSION OK")
    st, n, up = compound(sock, [op_sequence(sessionid, 10, 0),
                                op_putrootfh()], minor=1)
    check(st == nfsd.NFS4ERR_BADSESSION,
          "SEQUENCE on destroyed session -> BADSESSION")

    # 22. DESTROY_CLIENTID once sessionless
    st, n, up = compound(sock, [op_destroy_clientid(clientid)], minor=1)
    check(st == nfsd.NFS4_OK, "DESTROY_CLIENTID OK")

    # --- NFSv3 (RFC 1813) + MOUNT v3 --------------------------------------

    def v3(proc, body=b""):
        return rpc_call(sock, proc, body,
                        prog=nfsd.NFS_PROGRAM, vers=nfsd.NFS_V3)

    def m3(proc, body=b""):
        return rpc_call(sock, proc, body,
                        prog=nfsd.MOUNT_PROGRAM, vers=nfsd.MOUNT_V3)

    def skip_fattr3(up):
        up.opaque_fixed(84)            # fattr3 is a fixed 84-byte struct

    def skip_post_attr(up):
        if up.boolean():
            skip_fattr3(up)

    def skip_wcc(up):
        if up.boolean():
            up.opaque_fixed(24)        # wcc_attr: size + mtime + ctime
        skip_post_attr(up)

    # 23. MOUNT: NULL, then MNT of "/" returns the root filehandle
    m3(nfsd.MOUNTPROC3_NULL)
    check(True, "MOUNT3 NULL ping")
    pk = nfsd.Packer()
    pk.string("/")
    up = m3(nfsd.MOUNTPROC3_MNT, pk.get())
    check(up.uint32() == nfsd.MNT3_OK, "MOUNT3 MNT status OK")
    fh3 = up.opaque()
    check(len(fh3) == 8, "MOUNT3 MNT returns 8-byte root fh")
    nfl = up.uint32()
    flavors = [up.uint32() for _ in range(nfl)]
    check(nfsd.AUTH_SYS in flavors, "MOUNT3 MNT offers AUTH_SYS")

    # 24. NFS3 NULL + GETATTR of the root
    v3(nfsd.NFSPROC3_NULL)
    check(True, "NFS3 NULL ping")
    pk = nfsd.Packer()
    pk.opaque(fh3)
    up = v3(nfsd.NFSPROC3_GETATTR, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 GETATTR status OK")
    check(up.uint32() == nfsd.NF3DIR, "NFS3 root type is NF3DIR")

    # 25. CREATE (UNCHECKED, mode 0644) + WRITE + READ round-trip
    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("file3.txt")
    pk.uint32(nfsd.UNCHECKED)
    pk.boolean(True); pk.uint32(0o644)   # sattr3.mode
    pk.boolean(False); pk.boolean(False); pk.boolean(False)
    pk.uint32(nfsd.DONT_CHANGE); pk.uint32(nfsd.DONT_CHANGE)
    up = v3(nfsd.NFSPROC3_CREATE, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 CREATE status OK")
    check(up.boolean(), "NFS3 CREATE returns a filehandle")
    fh_file = up.opaque()

    pk = nfsd.Packer()
    pk.opaque(fh_file)
    pk.uint64(0)
    pk.uint32(9)
    pk.uint32(nfsd.FILE_SYNC)
    pk.opaque(b"v3 hello!")
    up = v3(nfsd.NFSPROC3_WRITE, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 WRITE status OK")
    skip_wcc(up)
    check(up.uint32() == 9, "NFS3 WRITE count 9")
    check(up.uint32() == nfsd.FILE_SYNC, "NFS3 WRITE committed FILE_SYNC")
    with open(os.path.join(export, "file3.txt"), "rb") as f:
        check(f.read() == b"v3 hello!", "NFS3 write visible on disk")

    pk = nfsd.Packer()
    pk.opaque(fh_file)
    pk.uint64(0)
    pk.uint32(100)
    up = v3(nfsd.NFSPROC3_READ, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 READ status OK")
    skip_post_attr(up)
    up.uint32()                          # count
    eof3 = up.boolean()
    check(up.opaque() == b"v3 hello!" and eof3, "NFS3 READ data + eof")

    # 26. LOOKUP finds it; SETATTR mode 0640 round-trips via GETATTR
    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("file3.txt")
    up = v3(nfsd.NFSPROC3_LOOKUP, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 LOOKUP status OK")
    check(up.opaque() == fh_file, "NFS3 LOOKUP returns same fh")

    pk = nfsd.Packer()
    pk.opaque(fh_file)
    pk.boolean(True); pk.uint32(0o640)   # sattr3.mode
    pk.boolean(False); pk.boolean(False); pk.boolean(False)
    pk.uint32(nfsd.DONT_CHANGE); pk.uint32(nfsd.DONT_CHANGE)
    pk.boolean(False)                    # sattrguard3: no check
    up = v3(nfsd.NFSPROC3_SETATTR, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 SETATTR status OK")
    pk = nfsd.Packer()
    pk.opaque(fh_file)
    up = v3(nfsd.NFSPROC3_GETATTR, pk.get())
    up.uint32()                          # status
    up.uint32()                          # type
    check(up.uint32() == 0o640, "NFS3 SETATTR mode round-trip")

    # 27. MKDIR + READDIRPLUS lists both entries
    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("dir3")
    pk.boolean(False); pk.boolean(False); pk.boolean(False); pk.boolean(False)
    pk.uint32(nfsd.DONT_CHANGE); pk.uint32(nfsd.DONT_CHANGE)
    up = v3(nfsd.NFSPROC3_MKDIR, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 MKDIR status OK")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.uint64(0)
    pk.opaque_fixed(b"\0" * 8)
    pk.uint32(4096)
    pk.uint32(65536)
    up = v3(nfsd.NFSPROC3_READDIRPLUS, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 READDIRPLUS status OK")
    skip_post_attr(up)
    up.opaque_fixed(8)                   # cookieverf
    seen = []
    while up.boolean():
        up.uint64()                      # fileid
        seen.append(up.string())
        up.uint64()                      # cookie
        skip_post_attr(up)
        if up.boolean():
            up.opaque()                  # name_handle
    up.boolean()                         # eof
    check(sorted(seen) >= ["dir3"] and "file3.txt" in seen,
          "NFS3 READDIRPLUS lists entries")

    # 28. FSINFO / PATHCONF / FSSTAT / ACCESS
    pk = nfsd.Packer()
    pk.opaque(fh3)
    up = v3(nfsd.NFSPROC3_FSINFO, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 FSINFO status OK")
    skip_post_attr(up)
    check(up.uint32() == nfsd.MAXIO, "NFS3 FSINFO rtmax")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    up = v3(nfsd.NFSPROC3_PATHCONF, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 PATHCONF status OK")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    up = v3(nfsd.NFSPROC3_FSSTAT, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 FSSTAT status OK")

    pk = nfsd.Packer()
    pk.opaque(fh_file)
    pk.uint32(nfsd.ACCESS3_READ | nfsd.ACCESS3_MODIFY)
    up = v3(nfsd.NFSPROC3_ACCESS, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 ACCESS status OK")
    skip_post_attr(up)
    check(up.uint32() & nfsd.ACCESS3_READ, "NFS3 ACCESS grants READ")

    # 29. RENAME, then REMOVE + RMDIR clean up; LOOKUP -> NOENT
    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("file3.txt")
    pk.opaque(fh3)
    pk.string("file3-renamed.txt")
    up = v3(nfsd.NFSPROC3_RENAME, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 RENAME status OK")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("file3-renamed.txt")
    up = v3(nfsd.NFSPROC3_REMOVE, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 REMOVE status OK")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("dir3")
    up = v3(nfsd.NFSPROC3_RMDIR, pk.get())
    check(up.uint32() == nfsd.NFS3_OK, "NFS3 RMDIR status OK")

    pk = nfsd.Packer()
    pk.opaque(fh3)
    pk.string("file3.txt")
    up = v3(nfsd.NFSPROC3_LOOKUP, pk.get())
    check(up.uint32() == nfsd.NFS3ERR_NOENT, "NFS3 LOOKUP gone -> NOENT")

    # 30. MOUNT EXPORT lists "/"
    up = m3(nfsd.MOUNTPROC3_EXPORT)
    check(up.boolean() and up.string() == "/",
          "MOUNT3 EXPORT lists the root")

    # --- portmapper v2 (RFC 1833) ------------------------------------------

    def pmap(proc, body=b""):
        return rpc_call(sock, proc, body,
                        prog=nfsd.PMAP_PROG, vers=nfsd.PMAP_VERS)

    def pmap_mapping(prog, vers, prot):
        pk = nfsd.Packer()
        pk.uint32(prog)
        pk.uint32(vers)
        pk.uint32(prot)
        pk.uint32(0)                     # port: ignored by GETPORT
        return pk.get()

    # 31. NULL + GETPORT over the same TCP listener
    pmap(nfsd.PMAPPROC_NULL)
    check(True, "PMAP NULL ping")
    up = pmap(nfsd.PMAPPROC_GETPORT,
              pmap_mapping(nfsd.MOUNT_PROGRAM, nfsd.MOUNT_V3,
                           nfsd.IPPROTO_TCP))
    check(up.uint32() == port, "PMAP GETPORT mountd/tcp -> server port")
    up = pmap(nfsd.PMAPPROC_GETPORT,
              pmap_mapping(nfsd.NFS_PROGRAM, nfsd.NFS_V3,
                           nfsd.IPPROTO_UDP))
    check(up.uint32() == 0, "PMAP GETPORT nfs/udp -> 0 (not registered)")

    # 32. DUMP lists the nfs v3/v4 and mountd mappings
    up = pmap(nfsd.PMAPPROC_DUMP)
    entries = []
    while up.boolean():
        entries.append(tuple(up.uint32() for _ in range(4)))
    check((nfsd.NFS_PROGRAM, nfsd.NFS_V3, nfsd.IPPROTO_TCP, port)
          in entries
          and (nfsd.NFS_PROGRAM, nfsd.NFS_V4, nfsd.IPPROTO_TCP, port)
          in entries
          and (nfsd.MOUNT_PROGRAM, nfsd.MOUNT_V3, nfsd.IPPROTO_TCP,
               port) in entries,
          "PMAP DUMP lists nfs v3+v4 and mountd")

    # 33. SET is refused on the static table
    up = pmap(nfsd.PMAPPROC_SET,
              pmap_mapping(300000, 1, nfsd.IPPROTO_TCP))
    check(up.uint32() == 0, "PMAP SET refused")

    # 34. GETPORT over UDP -- the transport BSD mount_nfs actually queries on
    usrv = nfsd.UdpServer(("127.0.0.1", 0), nfsd.UdpHandler)
    usrv.nfs = srv_nfs
    uport = usrv.server_address[1]
    nfsd._serve_in_thread(usrv)

    def udp_call(proc, body, prog, vers, dport=None):
        _xid[0] += 1
        xid = _xid[0]
        pk = nfsd.Packer()
        pk.uint32(xid)
        pk.uint32(nfsd.CALL)
        pk.uint32(nfsd.RPC_VERS)
        pk.uint32(prog)
        pk.uint32(vers)
        pk.uint32(proc)
        pk.uint32(nfsd.AUTH_NONE)
        pk.opaque(b"")
        pk.uint32(nfsd.AUTH_NONE)
        pk.uint32(0)
        pk.raw(body)
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        us.settimeout(10)
        try:
            us.sendto(pk.get(), ("127.0.0.1", uport if dport is None else dport))
            data, _ = us.recvfrom(65536)
        finally:
            us.close()
        up = nfsd.Unpacker(data)
        assert up.uint32() == xid, "udp xid mismatch"
        assert up.uint32() == nfsd.REPLY
        assert up.uint32() == nfsd.MSG_ACCEPTED, "udp rpc denied"
        up.uint32()
        up.opaque()                      # verifier
        assert up.uint32() == nfsd.SUCCESS
        return up

    up = udp_call(nfsd.PMAPPROC_GETPORT,
                  pmap_mapping(nfsd.NFS_PROGRAM, nfsd.NFS_V3,
                               nfsd.IPPROTO_TCP),
                  nfsd.PMAP_PROG, nfsd.PMAP_VERS)
    check(up.uint32() == port, "PMAP GETPORT over UDP -> server port")

    usrv.shutdown()
    usrv.server_close()

    # 35. wildcard fallback when a specific bind address is denied
    # (simulates the macOS 10.14+ rule: unprivileged binds below port 1024
    # succeed only on the wildcard address, a specific address gets
    # PermissionError). The wrapper classes deny every non-wildcard bind,
    # so start_pmap_servers must fall back to 0.0.0.0 and stay reachable.
    import io

    class DenySpecificTcp(nfsd.Server):
        def server_bind(self):
            if self.server_address[0] not in ("", "0.0.0.0", "::"):
                raise PermissionError(13, "Permission denied (simulated)")
            nfsd.Server.server_bind(self)

    class DenySpecificUdp(nfsd.UdpServer):
        def server_bind(self):
            if self.server_address[0] not in ("", "0.0.0.0", "::"):
                raise PermissionError(13, "Permission denied (simulated)")
            nfsd.UdpServer.server_bind(self)

    fb_port = 20112
    fb_out = io.StringIO()
    fb_srvs = nfsd.start_pmap_servers(srv_nfs, "127.0.0.1", fb_port,
                                      out=fb_out,
                                      tcp_cls=DenySpecificTcp,
                                      udp_cls=DenySpecificUdp)
    check(len(fb_srvs) == 2, "pmap fallback: tcp+udp listeners up")
    check(all(ps.server_address[0] == "0.0.0.0" for ps, _ in fb_srvs),
          "pmap fallback: bound on the wildcard address")
    check(fb_out.getvalue().count("needs root on this platform") == 2,
          "pmap fallback: reported for both listeners")
    for ps, _ in fb_srvs:
        nfsd._serve_in_thread(ps)
    up = udp_call(nfsd.PMAPPROC_GETPORT,
                  pmap_mapping(nfsd.NFS_PROGRAM, nfsd.NFS_V3,
                               nfsd.IPPROTO_TCP),
                  nfsd.PMAP_PROG, nfsd.PMAP_VERS, dport=fb_port)
    check(up.uint32() == port,
          "pmap fallback: GETPORT answers via loopback on the wildcard bind")
    for ps, _ in fb_srvs:
        ps.shutdown()
        ps.server_close()

    # 36. the REAL macOS rule on the real port 111 (darwin only, non-root):
    # a specific-address bind of a privileged port is denied while the
    # wildcard bind succeeds -- exactly what start_pmap_servers relies on.
    if sys.platform == "darwin" and os.getuid() != 0:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("0.0.0.0", nfsd.PMAP_PORT))
            port111_free = True
        except OSError:
            port111_free = False
        finally:
            probe.close()
        if port111_free:
            spec = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                spec.bind(("127.0.0.1", nfsd.PMAP_PORT))
                bound_specific = True
            except PermissionError:
                bound_specific = False
            finally:
                spec.close()
            check(not bound_specific,
                  "macos: specific-address bind of port 111 denied")
            mac_out = io.StringIO()
            mac_srvs = nfsd.start_pmap_servers(srv_nfs, "127.0.0.1",
                                               nfsd.PMAP_PORT, out=mac_out)
            check(len(mac_srvs) == 2
                  and all(ps.server_address[0] == "0.0.0.0"
                          for ps, _ in mac_srvs),
                  "macos: pmap fell back to the wildcard on port 111")
            for ps, _ in mac_srvs:
                nfsd._serve_in_thread(ps)
            up = udp_call(nfsd.PMAPPROC_GETPORT,
                          pmap_mapping(nfsd.MOUNT_PROGRAM, nfsd.MOUNT_V3,
                                       nfsd.IPPROTO_TCP),
                          nfsd.PMAP_PROG, nfsd.PMAP_VERS,
                          dport=nfsd.PMAP_PORT)
            check(up.uint32() == port,
                  "macos: GETPORT answers on the real port 111")
            for ps, _ in mac_srvs:
                ps.shutdown()
                ps.server_close()
        else:
            print("SKIP: port 111 already in use; macos pmap test skipped")

    # --- NFSv4.2 (RFC 7862): minorversion 2 on the 4.1 session layer -------

    # 37. a 4.2 session, then OPEN+WRITE to seed a file for the space ops
    st, n, up = compound(sock, [op_exchange_id(b"\x42" * 8, b"smoke42")],
                         minor=2)
    check(st == nfsd.NFS4_OK, "4.2 EXCHANGE_ID OK")
    up.uint32(); up.uint32()
    cid42 = up.uint64()
    seq42 = up.uint32()
    st, n, up = compound(sock, [op_create_session(cid42, seq42)], minor=2)
    check(st == nfsd.NFS4_OK, "4.2 CREATE_SESSION OK")
    up.uint32(); up.uint32()
    sid42 = up.opaque_fixed(nfsd.NFS4_SESSIONID_SIZE)
    sq = [0]

    def c42(ops):
        sq[0] += 1
        return compound(sock, [op_sequence(sid42, sq[0], 0)] + ops, minor=2)

    st, n, up = c42([op_reclaim_complete()])
    check(st == nfsd.NFS4_OK, "4.2 RECLAIM_COMPLETE OK")

    st, n, up = c42([op_putrootfh(), op_open41_create("file42.bin")])
    check(st == nfsd.NFS4_OK, "4.2 OPEN create OK")
    skip_sequence_res(up)
    up.uint32(); up.uint32()
    up.uint32(); up.uint32()
    osid42 = up.opaque_fixed(16)

    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_write41(osid42, 0, b"A" * 4096)])
    check(st == nfsd.NFS4_OK, "4.2 WRITE seed 4096 bytes")

    def op_seek(sid, offset, what):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_SEEK)
        pk.raw(sid)
        pk.uint64(offset)
        pk.uint32(what)
        return pk.get()

    def op_allocate(sid, offset, length, opnum=None):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_ALLOCATE if opnum is None else opnum)
        pk.raw(sid)
        pk.uint64(offset)
        pk.uint64(length)
        return pk.get()

    # 38. SEEK: data at 0, the virtual hole at EOF, NXIO past EOF
    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_seek(osid42, 0, nfsd.NFS4_CONTENT_DATA)])
    check(st == nfsd.NFS4_OK, "4.2 SEEK data status OK")
    skip_sequence_res(up)
    up.uint32(); up.uint32()
    up.uint32(); up.uint32()
    up.uint32(); up.uint32()
    up.boolean()                         # sr_eof
    check(up.uint64() == 0, "4.2 SEEK finds data at offset 0")

    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_seek(osid42, 0, nfsd.NFS4_CONTENT_HOLE)])
    check(st == nfsd.NFS4_OK, "4.2 SEEK hole status OK")

    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_seek(osid42, 999999, nfsd.NFS4_CONTENT_DATA)])
    check(st == nfsd.NFS4ERR_NXIO, "4.2 SEEK past EOF -> NXIO")

    # 39. ALLOCATE grows the file; DEALLOCATE zeroes a region
    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_allocate(osid42, 4096, 8192)])
    check(st == nfsd.NFS4_OK, "4.2 ALLOCATE status OK")
    check(os.path.getsize(os.path.join(export, "file42.bin")) == 12288,
          "4.2 ALLOCATE extended the file to 12288")

    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"),
                     op_allocate(osid42, 0, 2048, opnum=nfsd.OP_DEALLOCATE)])
    check(st == nfsd.NFS4_OK, "4.2 DEALLOCATE status OK")
    with open(os.path.join(export, "file42.bin"), "rb") as f:
        head = f.read(4096)
    check(head[:2048] == b"\0" * 2048 and head[2048:] == b"A" * 2048,
          "4.2 DEALLOCATE zeroed exactly the region")

    # 40. intra-server COPY: SAVEFH source -> PUTFH destination
    st, n, up = c42([op_putrootfh(), op_open41_create("copy-dst.bin")])
    check(st == nfsd.NFS4_OK, "4.2 OPEN copy destination")
    skip_sequence_res(up)
    up.uint32(); up.uint32()
    up.uint32(); up.uint32()
    dsid42 = up.opaque_fixed(16)

    def op_savefh():
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_SAVEFH)
        return pk.get()

    def op_copy(src_sid, dst_sid, src_off, dst_off, count):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_COPY)
        pk.raw(src_sid)
        pk.raw(dst_sid)
        pk.uint64(src_off)
        pk.uint64(dst_off)
        pk.uint64(count)
        pk.boolean(True)                 # ca_consecutive
        pk.boolean(True)                 # ca_synchronous
        pk.uint32(0)                     # ca_source_server<>: intra-server
        return pk.get()

    st, n, up = c42([op_putrootfh(), op_lookup("file42.bin"), op_savefh(),
                     op_putrootfh(), op_lookup("copy-dst.bin"),
                     op_copy(osid42, dsid42, 2048, 0, 2048)])
    check(st == nfsd.NFS4_OK, "4.2 COPY status OK")
    with open(os.path.join(export, "copy-dst.bin"), "rb") as f:
        check(f.read() == b"A" * 2048, "4.2 COPY moved the right bytes")

    # 41. the optional ops we do not implement answer NOTSUPP, not garbage
    def op_bare(opnum):
        pk = nfsd.Packer()
        pk.uint32(opnum)
        return pk.get()

    st, n, up = c42([op_putrootfh(), op_bare(nfsd.OP_CLONE)])
    check(st == nfsd.NFS4ERR_NOTSUPP, "4.2 CLONE -> NOTSUPP")
    st, n, up = c42([op_putrootfh(), op_bare(nfsd.OP_READ_PLUS)])
    check(st == nfsd.NFS4ERR_NOTSUPP, "4.2 READ_PLUS -> NOTSUPP")
    st, n, up = c42([op_putrootfh(), op_bare(nfsd.OP_IO_ADVISE)])
    check(st == nfsd.NFS4ERR_NOTSUPP, "4.2 IO_ADVISE -> NOTSUPP")

    # --- extended attributes (RFC 8276) -----------------------------------

    def op_getxattr(name):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_GETXATTR)
        pk.string(name)
        return pk.get()

    def op_setxattr(option, name, value):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_SETXATTR)
        pk.uint32(option)
        pk.string(name)
        pk.opaque(value)
        return pk.get()

    def op_removexattr(name):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_REMOVEXATTR)
        pk.string(name)
        return pk.get()

    def op_listxattrs(cookie, maxcount):
        pk = nfsd.Packer()
        pk.uint32(nfsd.OP_LISTXATTRS)
        pk.uint64(cookie)
        pk.uint32(maxcount)
        return pk.get()

    def xa_file(ops):
        return [op_putrootfh(), op_lookup("file42.bin")] + ops

    # An export on a filesystem that cannot store xattrs must decline the
    # whole feature rather than half-implement it, so the checks below
    # follow what the server advertises.
    xattr_ok = srv_nfs.xattr_ok
    print("xattr backend: %s" % ("posix" if srv_nfs.xattrs.posix else
                                 "darwin" if srv_nfs.xattrs.mac else
                                 "sidecar" if xattr_ok else "none"))

    def getattr_bitmap(up_):
        """Decode a GETATTR result into (returned-bitmap, values-reader)."""
        nw_ = up_.uint32()
        words_ = [up_.uint32() for _ in range(nw_)]
        return words_, nfsd.Unpacker(up_.opaque())

    def has_attr(words_, attr):
        w, b = divmod(attr, 32)
        return len(words_) > w and bool(words_[w] & (1 << b))

    # 43. xattr_support is a 4.2 attribute: advertised exactly when the
    # export can store xattrs, absent in 4.0 either way
    st, n, up = c42([op_putrootfh(),
                     op_getattr([nfsd.FATTR4_SUPPORTED_ATTRS,
                                 nfsd.FATTR4_XATTR_SUPPORT])])
    check(st == nfsd.NFS4_OK, "4.2 GETATTR xattr_support OK")
    skip_sequence_res(up)
    up.uint32(); up.uint32()             # PUTROOTFH
    up.uint32(); up.uint32()             # GETATTR opnum + status
    words, vals = getattr_bitmap(up)
    check(has_attr(words, nfsd.FATTR4_XATTR_SUPPORT) == xattr_ok,
          "4.2 GETATTR returns xattr_support iff supported")
    nsupp = vals.uint32()
    supp = [vals.uint32() for _ in range(nsupp)]
    check(has_attr(supp, nfsd.FATTR4_XATTR_SUPPORT) == xattr_ok,
          "4.2 supported_attrs advertises xattr_support iff supported")
    if xattr_ok:
        check(vals.boolean(), "4.2 xattr_support is TRUE")

    st, n, up = compound(sock, [op_putrootfh(),
                                op_getattr([nfsd.FATTR4_SUPPORTED_ATTRS,
                                            nfsd.FATTR4_XATTR_SUPPORT])])
    check(st == nfsd.NFS4_OK, "4.0 GETATTR still OK")
    up.uint32(); up.uint32()             # PUTROOTFH
    up.uint32(); up.uint32()             # GETATTR
    words0, vals0 = getattr_bitmap(up)
    check(not has_attr(words0, nfsd.FATTR4_XATTR_SUPPORT),
          "4.0 GETATTR does not return xattr_support")
    nsupp0 = vals0.uint32()
    supp0 = [vals0.uint32() for _ in range(nsupp0)]
    check(not has_attr(supp0, nfsd.FATTR4_XATTR_SUPPORT),
          "4.0 supported_attrs omits xattr_support")

    def xattr_supported_checks():
        # 44. GETXATTR of a missing key -> NOXATTR
        st_, n_, up_ = c42(xa_file([op_getxattr("user.attr1")]))
        check(st_ == nfsd.NFS4ERR_NOXATTR, "xattr GETXATTR missing -> NOXATTR")

        # 45. SETXATTR(CREATE) then GETXATTR round-trip
        st_, n_, up_ = c42(xa_file([op_setxattr(nfsd.SETXATTR4_CREATE,
                                                "user.attr1", b"value1")]))
        check(st_ == nfsd.NFS4_OK, "xattr SETXATTR create OK")
        st_, n_, up_ = c42(xa_file([op_getxattr("user.attr1")]))
        check(st_ == nfsd.NFS4_OK, "xattr GETXATTR OK")
        skip_sequence_res(up_)
        up_.uint32(); up_.uint32()
        up_.uint32(); up_.uint32()
        up_.uint32(); up_.uint32()
        check(up_.opaque() == b"value1", "xattr GETXATTR returns the value")

        # 46. CREATE of an existing key -> EXIST; REPLACE of missing -> NOXATTR
        st_, n_, up_ = c42(xa_file([op_setxattr(nfsd.SETXATTR4_CREATE,
                                                "user.attr1", b"other")]))
        check(st_ == nfsd.NFS4ERR_EXIST,
              "xattr SETXATTR create existing -> EXIST")
        st_, n_, up_ = c42(xa_file([op_setxattr(nfsd.SETXATTR4_REPLACE,
                                                "user.nope", b"x")]))
        check(st_ == nfsd.NFS4ERR_NOXATTR,
              "xattr SETXATTR replace missing -> NOXATTR")

        # 47. REPLACE and EITHER both update
        st_, n_, up_ = c42(xa_file([op_setxattr(nfsd.SETXATTR4_REPLACE,
                                                "user.attr1", b"value2")]))
        check(st_ == nfsd.NFS4_OK, "xattr SETXATTR replace OK")
        st_, n_, up_ = c42(xa_file([op_setxattr(nfsd.SETXATTR4_EITHER,
                                                "user.attr2", b"v2")]))
        check(st_ == nfsd.NFS4_OK, "xattr SETXATTR either creates")

        # 48. LISTXATTRS lists both keys with eof
        st_, n_, up_ = c42(xa_file([op_listxattrs(0, 8192)]))
        check(st_ == nfsd.NFS4_OK, "xattr LISTXATTRS OK")
        skip_sequence_res(up_)
        up_.uint32(); up_.uint32()
        up_.uint32(); up_.uint32()
        up_.uint32(); up_.uint32()
        up_.uint64()                     # lxr_cookie
        cnt = up_.uint32()
        listed = [up_.string() for _ in range(cnt)]
        check(up_.boolean(), "xattr LISTXATTRS eof set")
        check(sorted(listed) == ["user.attr1", "user.attr2"],
              "xattr LISTXATTRS lists both keys")

        # 49. REMOVEXATTR, then it is gone; removing again -> NOXATTR
        st_, n_, up_ = c42(xa_file([op_removexattr("user.attr2")]))
        check(st_ == nfsd.NFS4_OK, "xattr REMOVEXATTR OK")
        st_, n_, up_ = c42(xa_file([op_removexattr("user.attr2")]))
        check(st_ == nfsd.NFS4ERR_NOXATTR,
              "xattr REMOVEXATTR again -> NOXATTR")

        # 50. a maxcount too small for even one name -> TOOSMALL
        st_, n_, up_ = c42(xa_file([op_listxattrs(0, 8)]))
        check(st_ == nfsd.NFS4ERR_TOOSMALL,
              "xattr LISTXATTRS tiny -> TOOSMALL")

        # 51. the xattr ops are 4.2-only
        sq[0] += 1
        st_, n_, up_ = compound(sock, [op_sequence(sid42, sq[0], 0),
                                       op_putrootfh(),
                                       op_getxattr("user.attr1")], minor=1)
        check(st_ == nfsd.NFS4ERR_OP_ILLEGAL,
              "GETXATTR in a 4.1 compound -> ILLEGAL")

    def xattr_unsupported_checks():
        # an export whose filesystem cannot store xattrs must decline the
        # feature outright rather than half-implement it
        st_, n_, up_ = c42(xa_file([op_getxattr("user.attr1")]))
        check(st_ == nfsd.NFS4ERR_OP_ILLEGAL,
              "xattr declined: GETXATTR -> OP_ILLEGAL")
        st_, n_, up_ = c42(xa_file([op_listxattrs(0, 8192)]))
        check(st_ == nfsd.NFS4ERR_OP_ILLEGAL,
              "xattr declined: LISTXATTRS -> OP_ILLEGAL")

    if xattr_ok:
        xattr_supported_checks()
    else:
        xattr_unsupported_checks()

    # 42. a 4.2-only op must not exist in a 4.1 compound (same session:
    # the minorversion of the compound, not the session, picks the op table)
    sq[0] += 1
    st, n, up = compound(sock, [op_sequence(sid42, sq[0], 0),
                                op_putrootfh(), op_bare(nfsd.OP_SEEK)],
                         minor=1)
    check(st == nfsd.NFS4ERR_OP_ILLEGAL, "SEEK in a 4.1 compound -> ILLEGAL")

    # --- version gating (-vers 3 / -vers 4) --------------------------------

    # 37. a v3-only server: v4 refused with mismatch_info (3,3), v3 works
    srv3 = nfsd.Server(("127.0.0.1", 0), nfsd.ConnHandler)
    p3 = srv3.server_address[1]
    srv3.nfs = nfsd.NfsServer(export, p3, versions=(3,))
    nfsd._serve_in_thread(srv3)
    s3 = socket.create_connection(("127.0.0.1", p3), timeout=10)

    up = rpc_call(s3, nfsd.NFSPROC4_COMPOUND, b"",
                  accept=nfsd.PROG_MISMATCH)
    lo, hi = up.uint32(), up.uint32()
    check((lo, hi) == (nfsd.NFS_V3, nfsd.NFS_V3),
          "vers=3: v4 COMPOUND -> PROG_MISMATCH (3,3)")
    rpc_call(s3, nfsd.NFSPROC3_NULL, b"",
             prog=nfsd.NFS_PROGRAM, vers=nfsd.NFS_V3)
    check(True, "vers=3: NFS3 NULL accepted")
    pk = nfsd.Packer()
    pk.string("/")
    up = rpc_call(s3, nfsd.MOUNTPROC3_MNT, pk.get(),
                  prog=nfsd.MOUNT_PROGRAM, vers=nfsd.MOUNT_V3)
    check(up.uint32() == nfsd.MNT3_OK, "vers=3: MOUNT MNT works")
    up = rpc_call(s3, nfsd.PMAPPROC_DUMP, b"",
                  prog=nfsd.PMAP_PROG, vers=nfsd.PMAP_VERS)
    progs3 = set()
    while up.boolean():
        e = tuple(up.uint32() for _ in range(4))
        progs3.add((e[0], e[1]))
    check((nfsd.NFS_PROGRAM, nfsd.NFS_V4) not in progs3
          and (nfsd.NFS_PROGRAM, nfsd.NFS_V3) in progs3,
          "vers=3: portmapper only advertises v3")
    s3.close()
    srv3.shutdown()
    srv3.server_close()

    # 38. a v4-only server: v3 and MOUNT refused, v4 works
    srv4 = nfsd.Server(("127.0.0.1", 0), nfsd.ConnHandler)
    p4 = srv4.server_address[1]
    srv4.nfs = nfsd.NfsServer(export, p4, versions=(4,))
    nfsd._serve_in_thread(srv4)
    s4 = socket.create_connection(("127.0.0.1", p4), timeout=10)

    up = rpc_call(s4, nfsd.NFSPROC3_NULL, b"",
                  prog=nfsd.NFS_PROGRAM, vers=nfsd.NFS_V3,
                  accept=nfsd.PROG_MISMATCH)
    lo, hi = up.uint32(), up.uint32()
    check((lo, hi) == (nfsd.NFS_V4, nfsd.NFS_V4),
          "vers=4: NFS3 call -> PROG_MISMATCH (4,4)")
    rpc_call(s4, nfsd.MOUNTPROC3_NULL, b"",
             prog=nfsd.MOUNT_PROGRAM, vers=nfsd.MOUNT_V3,
             accept=nfsd.PROG_UNAVAIL)
    check(True, "vers=4: MOUNT program -> PROG_UNAVAIL")
    st, n, up = compound(s4, [op_putrootfh(), op_getfh()])
    check(st == nfsd.NFS4_OK, "vers=4: v4.0 compound works")
    s4.close()
    srv4.shutdown()
    srv4.server_close()

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
