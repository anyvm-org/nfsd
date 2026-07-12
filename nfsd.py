#!/usr/bin/env python3
"""nfsd.py - a cross-platform, user-space NFSv4.0 server in one pure-Python file.

Exports a single local directory over NFSv4.0 on a configurable TCP port.
Standard library only (sockets + basic filesystem operations); no kernel
module, no FUSE, no third-party dependencies. Runs on Linux, Windows, macOS.

Usage:
    python3 nfsd.py -dir /path/to/export -port 2049

Mount (Linux):
    mount -t nfs -o vers=4.0,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x

Protocol references:
    RFC 7530 - NFSv4.0 protocol
    RFC 7531 - NFSv4.0 XDR description (constants machine-extracted below)
    RFC 5531 - ONC RPC v2

State model: inode numbers and all NFS state (clients, opens, locks) are
in-memory for the lifetime of the process; after a restart old file handles
return NFS4ERR_STALE. AUTH_SYS and AUTH_NONE only.
"""

import argparse
import json
import logging
import os
import socket
import socketserver
import stat as statmod
import struct
import sys
import threading
import time

log = logging.getLogger("nfsd")

# === BEGIN GENERATED CONSTANTS (tools/gen_constants.py; DO NOT EDIT) ===
# Machine-extracted from the IETF specifications:
#   RFC 7531 (NFSv4.0 XDR)  -> spec/rfc7531.txt
#   RFC 5531 (ONC RPC v2)   -> spec/rfc5531.txt
# Regenerate with: python3 tools/gen_constants.py --splice nfsd.py

# --- RFC 7531 top-level consts ---
NFS4_FHSIZE = 128
NFS4_VERIFIER_SIZE = 8
NFS4_OTHER_SIZE = 12
NFS4_OPAQUE_LIMIT = 1024
NFS4_INT64_MAX = 9223372036854775807
NFS4_UINT64_MAX = 18446744073709551615
NFS4_INT32_MAX = 2147483647
NFS4_UINT32_MAX = 4294967295
ACL4_SUPPORT_ALLOW_ACL = 1
ACL4_SUPPORT_DENY_ACL = 2
ACL4_SUPPORT_AUDIT_ACL = 4
ACL4_SUPPORT_ALARM_ACL = 8
ACE4_ACCESS_ALLOWED_ACE_TYPE = 0
ACE4_ACCESS_DENIED_ACE_TYPE = 1
ACE4_SYSTEM_AUDIT_ACE_TYPE = 2
ACE4_SYSTEM_ALARM_ACE_TYPE = 3
ACE4_FILE_INHERIT_ACE = 1
ACE4_DIRECTORY_INHERIT_ACE = 2
ACE4_NO_PROPAGATE_INHERIT_ACE = 4
ACE4_INHERIT_ONLY_ACE = 8
ACE4_SUCCESSFUL_ACCESS_ACE_FLAG = 16
ACE4_FAILED_ACCESS_ACE_FLAG = 32
ACE4_IDENTIFIER_GROUP = 64
ACE4_READ_DATA = 1
ACE4_LIST_DIRECTORY = 1
ACE4_WRITE_DATA = 2
ACE4_ADD_FILE = 2
ACE4_APPEND_DATA = 4
ACE4_ADD_SUBDIRECTORY = 4
ACE4_READ_NAMED_ATTRS = 8
ACE4_WRITE_NAMED_ATTRS = 16
ACE4_EXECUTE = 32
ACE4_DELETE_CHILD = 64
ACE4_READ_ATTRIBUTES = 128
ACE4_WRITE_ATTRIBUTES = 256
ACE4_DELETE = 65536
ACE4_READ_ACL = 131072
ACE4_WRITE_ACL = 262144
ACE4_WRITE_OWNER = 524288
ACE4_SYNCHRONIZE = 1048576
ACE4_GENERIC_READ = 1179777
ACE4_GENERIC_WRITE = 1442054
ACE4_GENERIC_EXECUTE = 1179808
MODE4_SUID = 2048
MODE4_SGID = 1024
MODE4_SVTX = 512
MODE4_RUSR = 256
MODE4_WUSR = 128
MODE4_XUSR = 64
MODE4_RGRP = 32
MODE4_WGRP = 16
MODE4_XGRP = 8
MODE4_ROTH = 4
MODE4_WOTH = 2
MODE4_XOTH = 1
FH4_PERSISTENT = 0
FH4_NOEXPIRE_WITH_OPEN = 1
FH4_VOLATILE_ANY = 2
FH4_VOL_MIGRATION = 4
FH4_VOL_RENAME = 8
FATTR4_SUPPORTED_ATTRS = 0
FATTR4_TYPE = 1
FATTR4_FH_EXPIRE_TYPE = 2
FATTR4_CHANGE = 3
FATTR4_SIZE = 4
FATTR4_LINK_SUPPORT = 5
FATTR4_SYMLINK_SUPPORT = 6
FATTR4_NAMED_ATTR = 7
FATTR4_FSID = 8
FATTR4_UNIQUE_HANDLES = 9
FATTR4_LEASE_TIME = 10
FATTR4_RDATTR_ERROR = 11
FATTR4_FILEHANDLE = 19
FATTR4_ACL = 12
FATTR4_ACLSUPPORT = 13
FATTR4_ARCHIVE = 14
FATTR4_CANSETTIME = 15
FATTR4_CASE_INSENSITIVE = 16
FATTR4_CASE_PRESERVING = 17
FATTR4_CHOWN_RESTRICTED = 18
FATTR4_FILEID = 20
FATTR4_FILES_AVAIL = 21
FATTR4_FILES_FREE = 22
FATTR4_FILES_TOTAL = 23
FATTR4_FS_LOCATIONS = 24
FATTR4_HIDDEN = 25
FATTR4_HOMOGENEOUS = 26
FATTR4_MAXFILESIZE = 27
FATTR4_MAXLINK = 28
FATTR4_MAXNAME = 29
FATTR4_MAXREAD = 30
FATTR4_MAXWRITE = 31
FATTR4_MIMETYPE = 32
FATTR4_MODE = 33
FATTR4_NO_TRUNC = 34
FATTR4_NUMLINKS = 35
FATTR4_OWNER = 36
FATTR4_OWNER_GROUP = 37
FATTR4_QUOTA_AVAIL_HARD = 38
FATTR4_QUOTA_AVAIL_SOFT = 39
FATTR4_QUOTA_USED = 40
FATTR4_RAWDEV = 41
FATTR4_SPACE_AVAIL = 42
FATTR4_SPACE_FREE = 43
FATTR4_SPACE_TOTAL = 44
FATTR4_SPACE_USED = 45
FATTR4_SYSTEM = 46
FATTR4_TIME_ACCESS = 47
FATTR4_TIME_ACCESS_SET = 48
FATTR4_TIME_BACKUP = 49
FATTR4_TIME_CREATE = 50
FATTR4_TIME_DELTA = 51
FATTR4_TIME_METADATA = 52
FATTR4_TIME_MODIFY = 53
FATTR4_TIME_MODIFY_SET = 54
FATTR4_MOUNTED_ON_FILEID = 55
ACCESS4_READ = 1
ACCESS4_LOOKUP = 2
ACCESS4_MODIFY = 4
ACCESS4_EXTEND = 8
ACCESS4_DELETE = 16
ACCESS4_EXECUTE = 32
OPEN4_SHARE_ACCESS_READ = 1
OPEN4_SHARE_ACCESS_WRITE = 2
OPEN4_SHARE_ACCESS_BOTH = 3
OPEN4_SHARE_DENY_NONE = 0
OPEN4_SHARE_DENY_READ = 1
OPEN4_SHARE_DENY_WRITE = 2
OPEN4_SHARE_DENY_BOTH = 3
OPEN4_RESULT_CONFIRM = 2
OPEN4_RESULT_LOCKTYPE_POSIX = 4

# --- RFC 7531 enum nfs_ftype4 ---
NF4REG = 1
NF4DIR = 2
NF4BLK = 3
NF4CHR = 4
NF4LNK = 5
NF4SOCK = 6
NF4FIFO = 7
NF4ATTRDIR = 8
NF4NAMEDATTR = 9

# --- RFC 7531 enum nfsstat4 ---
NFS4_OK = 0
NFS4ERR_PERM = 1
NFS4ERR_NOENT = 2
NFS4ERR_IO = 5
NFS4ERR_NXIO = 6
NFS4ERR_ACCESS = 13
NFS4ERR_EXIST = 17
NFS4ERR_XDEV = 18
NFS4ERR_NOTDIR = 20
NFS4ERR_ISDIR = 21
NFS4ERR_INVAL = 22
NFS4ERR_FBIG = 27
NFS4ERR_NOSPC = 28
NFS4ERR_ROFS = 30
NFS4ERR_MLINK = 31
NFS4ERR_NAMETOOLONG = 63
NFS4ERR_NOTEMPTY = 66
NFS4ERR_DQUOT = 69
NFS4ERR_STALE = 70
NFS4ERR_BADHANDLE = 10001
NFS4ERR_BAD_COOKIE = 10003
NFS4ERR_NOTSUPP = 10004
NFS4ERR_TOOSMALL = 10005
NFS4ERR_SERVERFAULT = 10006
NFS4ERR_BADTYPE = 10007
NFS4ERR_DELAY = 10008
NFS4ERR_SAME = 10009
NFS4ERR_DENIED = 10010
NFS4ERR_EXPIRED = 10011
NFS4ERR_LOCKED = 10012
NFS4ERR_GRACE = 10013
NFS4ERR_FHEXPIRED = 10014
NFS4ERR_SHARE_DENIED = 10015
NFS4ERR_WRONGSEC = 10016
NFS4ERR_CLID_INUSE = 10017
NFS4ERR_RESOURCE = 10018
NFS4ERR_MOVED = 10019
NFS4ERR_NOFILEHANDLE = 10020
NFS4ERR_MINOR_VERS_MISMATCH = 10021
NFS4ERR_STALE_CLIENTID = 10022
NFS4ERR_STALE_STATEID = 10023
NFS4ERR_OLD_STATEID = 10024
NFS4ERR_BAD_STATEID = 10025
NFS4ERR_BAD_SEQID = 10026
NFS4ERR_NOT_SAME = 10027
NFS4ERR_LOCK_RANGE = 10028
NFS4ERR_SYMLINK = 10029
NFS4ERR_RESTOREFH = 10030
NFS4ERR_LEASE_MOVED = 10031
NFS4ERR_ATTRNOTSUPP = 10032
NFS4ERR_NO_GRACE = 10033
NFS4ERR_RECLAIM_BAD = 10034
NFS4ERR_RECLAIM_CONFLICT = 10035
NFS4ERR_BADXDR = 10036
NFS4ERR_LOCKS_HELD = 10037
NFS4ERR_OPENMODE = 10038
NFS4ERR_BADOWNER = 10039
NFS4ERR_BADCHAR = 10040
NFS4ERR_BADNAME = 10041
NFS4ERR_BAD_RANGE = 10042
NFS4ERR_LOCK_NOTSUPP = 10043
NFS4ERR_OP_ILLEGAL = 10044
NFS4ERR_DEADLOCK = 10045
NFS4ERR_FILE_OPEN = 10046
NFS4ERR_ADMIN_REVOKED = 10047
NFS4ERR_CB_PATH_DOWN = 10048

# --- RFC 7531 enum time_how4 ---
SET_TO_SERVER_TIME4 = 0
SET_TO_CLIENT_TIME4 = 1

# --- RFC 7531 enum nfs_lock_type4 ---
READ_LT = 1
WRITE_LT = 2
READW_LT = 3
WRITEW_LT = 4

# --- RFC 7531 enum createmode4 ---
UNCHECKED4 = 0
GUARDED4 = 1
EXCLUSIVE4 = 2

# --- RFC 7531 enum opentype4 ---
OPEN4_NOCREATE = 0
OPEN4_CREATE = 1

# --- RFC 7531 enum limit_by4 ---
NFS_LIMIT_SIZE = 1
NFS_LIMIT_BLOCKS = 2

# --- RFC 7531 enum open_delegation_type4 ---
OPEN_DELEGATE_NONE = 0
OPEN_DELEGATE_READ = 1
OPEN_DELEGATE_WRITE = 2

# --- RFC 7531 enum open_claim_type4 ---
CLAIM_NULL = 0
CLAIM_PREVIOUS = 1
CLAIM_DELEGATE_CUR = 2
CLAIM_DELEGATE_PREV = 3

# --- RFC 7531 enum rpc_gss_svc_t ---
RPC_GSS_SVC_NONE = 1
RPC_GSS_SVC_INTEGRITY = 2
RPC_GSS_SVC_PRIVACY = 3

# --- RFC 7531 enum stable_how4 ---
UNSTABLE4 = 0
DATA_SYNC4 = 1
FILE_SYNC4 = 2

# --- RFC 7531 enum nfs_opnum4 ---
OP_ACCESS = 3
OP_CLOSE = 4
OP_COMMIT = 5
OP_CREATE = 6
OP_DELEGPURGE = 7
OP_DELEGRETURN = 8
OP_GETATTR = 9
OP_GETFH = 10
OP_LINK = 11
OP_LOCK = 12
OP_LOCKT = 13
OP_LOCKU = 14
OP_LOOKUP = 15
OP_LOOKUPP = 16
OP_NVERIFY = 17
OP_OPEN = 18
OP_OPENATTR = 19
OP_OPEN_CONFIRM = 20
OP_OPEN_DOWNGRADE = 21
OP_PUTFH = 22
OP_PUTPUBFH = 23
OP_PUTROOTFH = 24
OP_READ = 25
OP_READDIR = 26
OP_READLINK = 27
OP_REMOVE = 28
OP_RENAME = 29
OP_RENEW = 30
OP_RESTOREFH = 31
OP_SAVEFH = 32
OP_SECINFO = 33
OP_SETATTR = 34
OP_SETCLIENTID = 35
OP_SETCLIENTID_CONFIRM = 36
OP_VERIFY = 37
OP_WRITE = 38
OP_RELEASE_LOCKOWNER = 39
OP_ILLEGAL = 10044

# --- RFC 7531 enum nfs_cb_opnum4 ---
OP_CB_GETATTR = 3
OP_CB_RECALL = 4
OP_CB_ILLEGAL = 10044

# --- RFC 7531 program declaration: NFS4_PROGRAM ---
NFS4_PROGRAM = 100003
NFS_V4 = 4
NFSPROC4_NULL = 0
NFSPROC4_COMPOUND = 1

# --- RFC 7531 program declaration: NFS4_CALLBACK ---
NFS4_CALLBACK = 1073741824
NFS_CB = 1
CB_NULL = 0
CB_COMPOUND = 1

# --- RFC 5531 enum auth_flavor ---
AUTH_NONE = 0
AUTH_SYS = 1
AUTH_SHORT = 2
AUTH_DH = 3
RPCSEC_GSS = 6

# --- RFC 5531 enum msg_type ---
CALL = 0
REPLY = 1

# --- RFC 5531 enum reply_stat ---
MSG_ACCEPTED = 0
MSG_DENIED = 1

# --- RFC 5531 enum accept_stat ---
SUCCESS = 0
PROG_UNAVAIL = 1
PROG_MISMATCH = 2
PROC_UNAVAIL = 3
GARBAGE_ARGS = 4
SYSTEM_ERR = 5

# --- RFC 5531 enum reject_stat ---
RPC_MISMATCH = 0
AUTH_ERROR = 1

# --- RFC 5531 enum auth_stat ---
AUTH_OK = 0
AUTH_BADCRED = 1
AUTH_REJECTEDCRED = 2
AUTH_BADVERF = 3
AUTH_REJECTEDVERF = 4
AUTH_TOOWEAK = 5
AUTH_INVALIDRESP = 6
AUTH_FAILED = 7
AUTH_KERB_GENERIC = 8
AUTH_TIMEEXPIRE = 9
AUTH_TKT_FILE = 10
AUTH_DECODE = 11
AUTH_NET_ADDR = 12
RPCSEC_GSS_CREDPROBLEM = 13
RPCSEC_GSS_CTXPROBLEM = 14

NFSSTAT4_NAMES = {
    0: 'NFS4_OK',
    1: 'NFS4ERR_PERM',
    2: 'NFS4ERR_NOENT',
    5: 'NFS4ERR_IO',
    6: 'NFS4ERR_NXIO',
    13: 'NFS4ERR_ACCESS',
    17: 'NFS4ERR_EXIST',
    18: 'NFS4ERR_XDEV',
    20: 'NFS4ERR_NOTDIR',
    21: 'NFS4ERR_ISDIR',
    22: 'NFS4ERR_INVAL',
    27: 'NFS4ERR_FBIG',
    28: 'NFS4ERR_NOSPC',
    30: 'NFS4ERR_ROFS',
    31: 'NFS4ERR_MLINK',
    63: 'NFS4ERR_NAMETOOLONG',
    66: 'NFS4ERR_NOTEMPTY',
    69: 'NFS4ERR_DQUOT',
    70: 'NFS4ERR_STALE',
    10001: 'NFS4ERR_BADHANDLE',
    10003: 'NFS4ERR_BAD_COOKIE',
    10004: 'NFS4ERR_NOTSUPP',
    10005: 'NFS4ERR_TOOSMALL',
    10006: 'NFS4ERR_SERVERFAULT',
    10007: 'NFS4ERR_BADTYPE',
    10008: 'NFS4ERR_DELAY',
    10009: 'NFS4ERR_SAME',
    10010: 'NFS4ERR_DENIED',
    10011: 'NFS4ERR_EXPIRED',
    10012: 'NFS4ERR_LOCKED',
    10013: 'NFS4ERR_GRACE',
    10014: 'NFS4ERR_FHEXPIRED',
    10015: 'NFS4ERR_SHARE_DENIED',
    10016: 'NFS4ERR_WRONGSEC',
    10017: 'NFS4ERR_CLID_INUSE',
    10018: 'NFS4ERR_RESOURCE',
    10019: 'NFS4ERR_MOVED',
    10020: 'NFS4ERR_NOFILEHANDLE',
    10021: 'NFS4ERR_MINOR_VERS_MISMATCH',
    10022: 'NFS4ERR_STALE_CLIENTID',
    10023: 'NFS4ERR_STALE_STATEID',
    10024: 'NFS4ERR_OLD_STATEID',
    10025: 'NFS4ERR_BAD_STATEID',
    10026: 'NFS4ERR_BAD_SEQID',
    10027: 'NFS4ERR_NOT_SAME',
    10028: 'NFS4ERR_LOCK_RANGE',
    10029: 'NFS4ERR_SYMLINK',
    10030: 'NFS4ERR_RESTOREFH',
    10031: 'NFS4ERR_LEASE_MOVED',
    10032: 'NFS4ERR_ATTRNOTSUPP',
    10033: 'NFS4ERR_NO_GRACE',
    10034: 'NFS4ERR_RECLAIM_BAD',
    10035: 'NFS4ERR_RECLAIM_CONFLICT',
    10036: 'NFS4ERR_BADXDR',
    10037: 'NFS4ERR_LOCKS_HELD',
    10038: 'NFS4ERR_OPENMODE',
    10039: 'NFS4ERR_BADOWNER',
    10040: 'NFS4ERR_BADCHAR',
    10041: 'NFS4ERR_BADNAME',
    10042: 'NFS4ERR_BAD_RANGE',
    10043: 'NFS4ERR_LOCK_NOTSUPP',
    10044: 'NFS4ERR_OP_ILLEGAL',
    10045: 'NFS4ERR_DEADLOCK',
    10046: 'NFS4ERR_FILE_OPEN',
    10047: 'NFS4ERR_ADMIN_REVOKED',
    10048: 'NFS4ERR_CB_PATH_DOWN',
}

OP_NAMES = {
    3: 'OP_ACCESS',
    4: 'OP_CLOSE',
    5: 'OP_COMMIT',
    6: 'OP_CREATE',
    7: 'OP_DELEGPURGE',
    8: 'OP_DELEGRETURN',
    9: 'OP_GETATTR',
    10: 'OP_GETFH',
    11: 'OP_LINK',
    12: 'OP_LOCK',
    13: 'OP_LOCKT',
    14: 'OP_LOCKU',
    15: 'OP_LOOKUP',
    16: 'OP_LOOKUPP',
    17: 'OP_NVERIFY',
    18: 'OP_OPEN',
    19: 'OP_OPENATTR',
    20: 'OP_OPEN_CONFIRM',
    21: 'OP_OPEN_DOWNGRADE',
    22: 'OP_PUTFH',
    23: 'OP_PUTPUBFH',
    24: 'OP_PUTROOTFH',
    25: 'OP_READ',
    26: 'OP_READDIR',
    27: 'OP_READLINK',
    28: 'OP_REMOVE',
    29: 'OP_RENAME',
    30: 'OP_RENEW',
    31: 'OP_RESTOREFH',
    32: 'OP_SAVEFH',
    33: 'OP_SECINFO',
    34: 'OP_SETATTR',
    35: 'OP_SETCLIENTID',
    36: 'OP_SETCLIENTID_CONFIRM',
    37: 'OP_VERIFY',
    38: 'OP_WRITE',
    39: 'OP_RELEASE_LOCKOWNER',
    10044: 'OP_ILLEGAL',
}
# === END GENERATED CONSTANTS ===

# --- hand-written protocol constants, each cited to its spec text ---

# RFC 5531 sec 9, struct call_body: "unsigned int rpcvers; /* must be equal
# to two (2) */"
RPC_VERS = 2

# RFC 5531 sec 11 (Record Marking Standard): the highest-order bit of the
# 4-byte record fragment header is the last-fragment flag ("bit value 1
# implies the fragment is the last fragment"); the remaining 31 bits are the
# fragment length.
RM_LAST_FRAGMENT = 0x80000000

IS_WINDOWS = os.name == "nt"
MAXIO = 1048576              # advertised maxread/maxwrite
MAX_RPC_RECORD = 4 * 1024 * 1024
FSID_MAJOR = 0x6E667364      # arbitrary but stable fsid ("nfsd")
SIDE_STREAM = ":nfsd.meta"   # NTFS ADS sidecar for uid/gid/mode on Windows


# ---------------------------------------------------------------------------
# XDR primitives (RFC 4506): big-endian, 4-byte alignment
# ---------------------------------------------------------------------------

class XdrError(Exception):
    pass


class Unpacker(object):
    __slots__ = ("data", "pos")

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _take(self, n):
        p = self.pos
        if p + n > len(self.data):
            raise XdrError("short buffer: need %d at %d/%d" % (n, p, len(self.data)))
        self.pos = p + n
        return p

    def uint32(self):
        return struct.unpack_from(">I", self.data, self._take(4))[0]

    def int32(self):
        return struct.unpack_from(">i", self.data, self._take(4))[0]

    def uint64(self):
        return struct.unpack_from(">Q", self.data, self._take(8))[0]

    def int64(self):
        return struct.unpack_from(">q", self.data, self._take(8))[0]

    def boolean(self):
        return self.uint32() != 0

    def opaque_fixed(self, n):
        p = self._take(n + ((4 - (n & 3)) & 3))
        return bytes(self.data[p:p + n])

    def opaque(self, maxlen=None):
        n = self.uint32()
        if maxlen is not None and n > maxlen:
            raise XdrError("opaque too long: %d > %d" % (n, maxlen))
        if n > len(self.data):
            raise XdrError("opaque length exceeds buffer")
        return self.opaque_fixed(n)

    def string(self, maxlen=None):
        return self.opaque(maxlen).decode("utf-8", "surrogateescape")


class Packer(object):
    __slots__ = ("buf",)

    def __init__(self):
        self.buf = bytearray()

    def raw(self, b):
        self.buf += b

    def uint32(self, v):
        self.buf += struct.pack(">I", v & 0xFFFFFFFF)

    def uint64(self, v):
        self.buf += struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)

    def int64(self, v):
        self.buf += struct.pack(">q", v)

    def boolean(self, v):
        self.uint32(1 if v else 0)

    def opaque_fixed(self, b):
        self.buf += b
        pad = (4 - (len(b) & 3)) & 3
        if pad:
            self.buf += b"\0" * pad

    def opaque(self, b):
        self.uint32(len(b))
        self.opaque_fixed(b)

    def string(self, s):
        self.opaque(s.encode("utf-8", "surrogateescape"))

    def get(self):
        return bytes(self.buf)


def pack_bitmap(attrs):
    """Encode a bitmap4 from an iterable of attribute numbers."""
    words = []
    for a in attrs:
        w = a // 32
        while len(words) <= w:
            words.append(0)
        words[w] |= 1 << (a % 32)
    pk = Packer()
    pk.uint32(len(words))
    for w in words:
        pk.uint32(w)
    return pk.get()


def unpack_bitmap(up):
    """Decode a bitmap4 into an ascending list of attribute numbers.

    Unknown high bits are legal on the wire (GETATTR must simply ignore
    attributes it does not know), so accept generously sized bitmaps.
    """
    n = up.uint32()
    if n > 1024:
        raise XdrError("bitmap too large")
    out = []
    for i in range(n):
        w = up.uint32()
        b = 0
        while w:
            if w & 1:
                out.append(i * 32 + b)
            w >>= 1
            b += 1
    return out


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class NfsErr(Exception):
    def __init__(self, stat, msg=""):
        Exception.__init__(self, msg or NFSSTAT4_NAMES.get(stat, str(stat)))
        self.stat = stat


_ERRNO_MAP = None


def oserror_to_stat(e):
    global _ERRNO_MAP
    if _ERRNO_MAP is None:
        import errno
        _ERRNO_MAP = {
            errno.EPERM: NFS4ERR_PERM,
            errno.ENOENT: NFS4ERR_NOENT,
            errno.EIO: NFS4ERR_IO,
            errno.EACCES: NFS4ERR_ACCESS,
            errno.EEXIST: NFS4ERR_EXIST,
            errno.EXDEV: NFS4ERR_XDEV,
            errno.ENOTDIR: NFS4ERR_NOTDIR,
            errno.EISDIR: NFS4ERR_ISDIR,
            errno.EINVAL: NFS4ERR_INVAL,
            errno.EFBIG: NFS4ERR_FBIG,
            errno.ENOSPC: NFS4ERR_NOSPC,
            errno.EROFS: NFS4ERR_ROFS,
            errno.EMLINK: NFS4ERR_MLINK,
            errno.ENAMETOOLONG: NFS4ERR_NAMETOOLONG,
            errno.ENOTEMPTY: NFS4ERR_NOTEMPTY,
            errno.EDQUOT: NFS4ERR_DQUOT,
            errno.ESTALE: NFS4ERR_STALE,
        }
    return _ERRNO_MAP.get(getattr(e, "errno", None), NFS4ERR_IO)


# ---------------------------------------------------------------------------
# inode map: synthetic inode <-> dentry (parent inode, name)
# ---------------------------------------------------------------------------

ROOT_INO = 1


class InodeMap(object):
    """In-memory dentry model, like the proven Java implementation: each
    inode stores (parent, name); paths are rebuilt by walking to the root,
    so a directory rename is O(1) and keeps every descendant handle valid.
    Inode numbers are never reused: a dead handle resolves to nothing and
    surfaces as NFS4ERR_STALE."""

    def __init__(self, root):
        self.root = root
        self.lock = threading.Lock()
        self.dent = {ROOT_INO: (0, "")}       # ino -> (parent ino, name)
        self.kids = {}                        # parent ino -> {name: ino}
        self.next_ino = ROOT_INO + 1

    def path_of(self, ino):
        if ino == ROOT_INO:
            return self.root
        parts = []
        cur = ino
        with self.lock:
            for _ in range(4096):  # depth guard
                if cur == ROOT_INO:
                    break
                d = self.dent.get(cur)
                if d is None:
                    raise NfsErr(NFS4ERR_STALE, "ino %d" % ino)
                parts.append(d[1])
                cur = d[0]
            else:
                raise NfsErr(NFS4ERR_STALE, "loop for ino %d" % ino)
        parts.reverse()
        return os.path.join(self.root, *parts)

    def parent_of(self, ino):
        with self.lock:
            d = self.dent.get(ino)
        if d is None:
            raise NfsErr(NFS4ERR_STALE, "ino %d" % ino)
        return d[0]

    def get_child(self, parent, name):
        with self.lock:
            m = self.kids.get(parent)
            return m.get(name, 0) if m else 0

    def get_or_alloc(self, parent, name):
        with self.lock:
            m = self.kids.setdefault(parent, {})
            ino = m.get(name)
            if ino:
                return ino
            ino = self.next_ino
            self.next_ino += 1
            m[name] = ino
            self.dent[ino] = (parent, name)
            return ino

    def remove_child(self, parent, name):
        with self.lock:
            m = self.kids.get(parent)
            if not m:
                return 0
            ino = m.pop(name, 0)
            if ino:
                self.dent.pop(ino, None)
                self.kids.pop(ino, None)
            return ino

    def move(self, sparent, oldname, dparent, newname):
        with self.lock:
            sm = self.kids.setdefault(sparent, {})
            ino = sm.pop(oldname, 0)
            if not ino:
                ino = self.next_ino
                self.next_ino += 1
            dm = self.kids.setdefault(dparent, {})
            replaced = dm.get(newname, 0)
            if replaced and replaced != ino:
                self.dent.pop(replaced, None)
                self.kids.pop(replaced, None)
            dm[newname] = ino
            self.dent[ino] = (dparent, newname)
            return ino, replaced

    def count(self):
        with self.lock:
            return len(self.dent)


def fh_bytes(ino):
    return struct.pack(">Q", ino)


def fh_ino(b):
    if len(b) != 8:
        raise NfsErr(NFS4ERR_BADHANDLE)
    return struct.unpack(">Q", b)[0]


# ---------------------------------------------------------------------------
# open-file handle cache (the Java version's WriteChannelCache lesson:
# per-op open/close dominates write cost; reuse descriptors keyed by inode)
# ---------------------------------------------------------------------------

class _Ent(object):
    __slots__ = ("fd", "lock", "writable")

    def __init__(self, fd, writable):
        self.fd = fd
        self.lock = threading.Lock()
        self.writable = writable


class FileCache(object):
    def __init__(self, cap=128):
        self.cap = cap
        self.lock = threading.Lock()
        self.ents = {}          # ino -> _Ent
        self.order = []         # rough LRU

    def _open(self, path, writable):
        flags = os.O_RDWR if writable else os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        return os.open(path, flags)

    def get(self, ino, path, writable):
        with self.lock:
            e = self.ents.get(ino)
            if e is not None and (e.writable or not writable):
                return e
            if e is not None:
                self._drop_locked(ino)
            fd = self._open(path, writable)
            e = _Ent(fd, writable)
            self.ents[ino] = e
            self.order.append(ino)
            while len(self.ents) > self.cap:
                old = self.order.pop(0)
                if old in self.ents and old != ino:
                    self._drop_locked(old)
            return e

    def _drop_locked(self, ino):
        e = self.ents.pop(ino, None)
        if e is not None:
            try:
                os.close(e.fd)
            except OSError:
                pass

    def invalidate(self, ino):
        with self.lock:
            self._drop_locked(ino)

    def close_all(self):
        with self.lock:
            for ino in list(self.ents):
                self._drop_locked(ino)

    # positional I/O; os.pread/os.pwrite are POSIX-only, so fall back to
    # seek+read under the per-entry lock on Windows
    if hasattr(os, "pread"):
        @staticmethod
        def pread(e, n, off):
            return os.pread(e.fd, n, off)

        @staticmethod
        def pwrite(e, data, off):
            return os.pwrite(e.fd, data, off)
    else:
        @staticmethod
        def pread(e, n, off):
            with e.lock:
                os.lseek(e.fd, off, os.SEEK_SET)
                return os.read(e.fd, n)

        @staticmethod
        def pwrite(e, data, off):
            with e.lock:
                os.lseek(e.fd, off, os.SEEK_SET)
                return os.write(e.fd, data)

    @staticmethod
    def size(e):
        return os.fstat(e.fd).st_size

    @staticmethod
    def fsync(e):
        os.fsync(e.fd)

    @staticmethod
    def ftruncate(e, n):
        os.ftruncate(e.fd, n)


# ---------------------------------------------------------------------------
# NFSv4 state: clients, opens, byte-range locks (all in-memory)
# ---------------------------------------------------------------------------

SEQID_NO_ADV = frozenset([
    NFS4ERR_STALE_CLIENTID, NFS4ERR_STALE_STATEID, NFS4ERR_BAD_STATEID,
    NFS4ERR_BAD_SEQID, NFS4ERR_BADXDR, NFS4ERR_RESOURCE, NFS4ERR_NOFILEHANDLE,
])


class _Client(object):
    __slots__ = ("clientid", "verifier", "owner_id", "confirm", "confirmed",
                 "last_renew", "principal")

    def __init__(self, clientid, verifier, owner_id, confirm, principal):
        self.clientid = clientid
        self.verifier = verifier
        self.owner_id = owner_id
        self.confirm = confirm
        self.confirmed = False
        self.last_renew = time.monotonic()
        self.principal = principal


class _Owner(object):
    """An open-owner or lock-owner: tracks the sequence id and the cached
    reply of the last non-idempotent operation (for exactly-once replay)."""
    __slots__ = ("key", "seqid", "reply", "confirmed")

    def __init__(self, key):
        self.key = key           # (clientid, owner_bytes)
        self.seqid = None        # last processed owner seqid
        self.reply = None        # (seqid, body_bytes)
        self.confirmed = False   # open-owner only: has OPEN_CONFIRM happened


class _Open(object):
    __slots__ = ("other", "gen", "ino", "access", "deny", "owner_key",
                 "confirmed", "modes", "opener_uid")

    def __init__(self, other, ino, access, deny, owner_key, opener_uid):
        self.other = other
        self.gen = 1
        self.ino = ino
        self.access = access
        self.deny = deny
        self.owner_key = owner_key
        self.confirmed = False
        self.modes = {(access, deny)}     # explicitly-requested share modes
        self.opener_uid = opener_uid


class _LockState(object):
    __slots__ = ("other", "gen", "ino", "owner")

    def __init__(self, other, ino, owner):
        self.other = other
        self.gen = 1
        self.ino = ino
        self.owner = owner       # (clientid, lock owner bytes)


MAX_END = 0xFFFFFFFFFFFFFFFF


class State(object):
    def __init__(self, lease=90):
        self.lock = threading.RLock()
        self.lease = lease
        self.boot_epoch = int(time.time()) & 0x7FFFFFFF
        self.next_clientid = 1
        self.next_state = 1
        self.clients = {}           # clientid -> _Client
        self.by_owner_id = {}       # owner id bytes -> clientid (confirmed)
        self.open_owners = {}       # (clientid, owner) -> _Owner
        self.lock_owners = {}       # (clientid, owner) -> _Owner
        self.opens = {}             # other -> _Open
        self.opens_by_key = {}      # (clientid, owner, ino) -> _Open
        self.other_owner = {}       # open other -> owner key (survives close)
        self.lock_states = {}       # other -> _LockState
        self.lock_by_key = {}       # (clientid, owner, ino) -> _LockState
        self.locks = {}             # ino -> [(owner, type, start, end)]
        self.expired = set()        # stateid others invalidated by lease loss

    def _purge_client_locked(self, clientid):
        """Drop all opens/locks/owners of a clientid (lease expiry or a new
        confirmed incarnation). Their stateids become NFS4ERR_EXPIRED."""
        for other in [k for k, o in self.opens.items()
                      if o.owner_key[0] == clientid]:
            o = self.opens.pop(other)
            self.opens_by_key.pop((o.owner_key[0], o.owner_key[1], o.ino), None)
            self.expired.add(other)
        for other in [k for k, ls in self.lock_states.items()
                      if ls.owner[0] == clientid]:
            ls = self.lock_states.pop(other)
            self.lock_by_key.pop((ls.owner[0], ls.owner[1], ls.ino), None)
            self.expired.add(other)
        for key in [k for k in self.open_owners if k[0] == clientid]:
            self.open_owners.pop(key, None)
        for key in [k for k in self.lock_owners if k[0] == clientid]:
            self.lock_owners.pop(key, None)
        for ino in list(self.locks):
            keep = [r for r in self.locks[ino] if r[0][0] != clientid]
            if keep:
                self.locks[ino] = keep
            else:
                self.locks.pop(ino, None)

    def _new_other(self):
        n = self.next_state
        self.next_state += 1
        return struct.pack(">I", self.boot_epoch) + struct.pack(">Q", n)

    # -- clients ---------------------------------------------------------
    def setclientid(self, verifier, owner_id, principal):
        with self.lock:
            cur_id = self.by_owner_id.get(owner_id)
            cur = self.clients.get(cur_id) if cur_id else None
            if cur is not None:
                # a confirmed record exists for this id string
                if cur.principal != principal:
                    # different principal owns the id and it has state
                    if self._client_has_state(cur.clientid):
                        raise NfsErr(NFS4ERR_CLID_INUSE)
                if cur.verifier == verifier and cur.principal == principal:
                    # same client re-registering (callback update): reuse
                    cur.confirm = os.urandom(8)
                    return cur.clientid, cur.confirm
            # remove any prior unconfirmed record for this id string
            for cid in [k for k, c in self.clients.items()
                        if c.owner_id == owner_id and not c.confirmed]:
                self.clients.pop(cid, None)
            clientid = self.next_clientid
            self.next_clientid += 1
            confirm = os.urandom(8)
            self.clients[clientid] = _Client(clientid, verifier, owner_id,
                                             confirm, principal)
            return clientid, confirm

    def _client_has_state(self, clientid):
        return (any(o.owner_key[0] == clientid for o in self.opens.values())
                or any(ls.owner[0] == clientid for ls in self.lock_states.values()))

    def confirm_client(self, clientid, confirm):
        with self.lock:
            c = self.clients.get(clientid)
            if c is None:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if c.confirm != confirm:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if not c.confirmed:
                prev = self.by_owner_id.get(c.owner_id)
                if prev is not None and prev != clientid:
                    self.clients.pop(prev, None)
                    self._purge_client_locked(prev)
                c.confirmed = True
                self.by_owner_id[c.owner_id] = clientid
            c.last_renew = time.monotonic()

    def check_client(self, clientid):
        with self.lock:
            c = self.clients.get(clientid)
            if c is None or not c.confirmed:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if time.monotonic() - c.last_renew > self.lease:
                self._purge_client_locked(clientid)
                raise NfsErr(NFS4ERR_EXPIRED)
            c.last_renew = time.monotonic()

    def touch_client(self, clientid):
        with self.lock:
            c = self.clients.get(clientid)
            if c is not None:
                c.last_renew = time.monotonic()

    # -- owners / seqid --------------------------------------------------
    def open_owner(self, clientid, owner_bytes):
        key = (clientid, owner_bytes)
        with self.lock:
            o = self.open_owners.get(key)
            if o is None:
                o = _Owner(key)
                self.open_owners[key] = o
            return o

    def lock_owner(self, clientid, owner_bytes):
        key = (clientid, owner_bytes)
        with self.lock:
            o = self.lock_owners.get(key)
            if o is None:
                o = _Owner(key)
                self.lock_owners[key] = o
            return o

    def seqid_check(self, owner, seqid):
        """Return ('process', None) or ('replay', cached_body); raise
        NFS4ERR_BAD_SEQID otherwise."""
        if owner.seqid is None:
            return ("process", None)
        nxt = (owner.seqid + 1) & 0xFFFFFFFF
        if seqid == nxt:
            return ("process", None)
        if seqid == owner.seqid and owner.reply is not None:
            return ("replay", owner.reply[1])
        raise NfsErr(NFS4ERR_BAD_SEQID)

    def seqid_commit(self, owner, seqid, body):
        status = struct.unpack_from(">I", body)[0]
        if status not in SEQID_NO_ADV:
            owner.seqid = seqid
            owner.reply = (seqid, body)
        return body

    # -- stateid resolution ----------------------------------------------
    def resolve_stateid(self, sid, ino=None):
        """Return the _Open/_LockState for a real stateid (None for the
        special stateids). Raises STALE/OLD/BAD_STATEID / EXPIRED."""
        if sid == ZERO_STATEID or sid == ONES_STATEID:
            return None
        gen, other = sid
        epoch = struct.unpack(">I", other[0:4])[0]
        if epoch != self.boot_epoch:
            raise NfsErr(NFS4ERR_STALE_STATEID if epoch < self.boot_epoch
                         else NFS4ERR_BAD_STATEID)
        with self.lock:
            st = self.opens.get(other)
            if st is None:
                st = self.lock_states.get(other)
            if st is None:
                if other in self.expired:
                    raise NfsErr(NFS4ERR_EXPIRED)
                raise NfsErr(NFS4ERR_BAD_STATEID)
            if gen != 0:
                if gen < st.gen:
                    raise NfsErr(NFS4ERR_OLD_STATEID)
                if gen > st.gen:
                    raise NfsErr(NFS4ERR_BAD_STATEID)
            if ino is not None and st.ino != ino:
                raise NfsErr(NFS4ERR_BAD_STATEID)
            return st

    # -- share reservations ----------------------------------------------
    def opens_of(self, ino):
        return [o for o in self.opens.values() if o.ino == ino]

    def share_conflict(self, ino, access, deny, owner_key):
        # A new OPEN's access must not hit any existing open's deny, and its
        # deny must not hit any existing access -- INCLUDING the same owner's
        # own prior share (RFC 7530 sec 9.9 / 15.22.5).
        with self.lock:
            for o in self.opens.values():
                if o.ino != ino:
                    continue
                if (access & o.deny) or (deny & o.access):
                    return True
            return False

    def io_deny_conflict(self, ino, writing):
        """True if an anonymous READ/WRITE is blocked by some open's deny."""
        want = OPEN4_SHARE_DENY_WRITE if writing else OPEN4_SHARE_DENY_READ
        with self.lock:
            return any(o.ino == ino and (o.deny & want)
                       for o in self.opens.values())

    # -- opens -----------------------------------------------------------
    def open_file(self, clientid, owner_bytes, ino, access, deny, opener_uid):
        key = (clientid, owner_bytes, ino)
        with self.lock:
            o = self.opens_by_key.get(key)
            if o is not None:
                o.access |= access
                o.deny |= deny
                o.modes.add((access, deny))
                o.gen += 1
                return o, False
            o = _Open(self._new_other(), ino, access, deny,
                      (clientid, owner_bytes), opener_uid)
            self.opens[o.other] = o
            self.opens_by_key[key] = o
            self.other_owner[o.other] = (clientid, owner_bytes)
            return o, True

    def owner_of_other(self, other):
        return self.other_owner.get(other)

    def get_open(self, other):
        with self.lock:
            return self.opens.get(other)

    def close_open(self, o):
        with self.lock:
            self.opens.pop(o.other, None)
            self.opens_by_key.pop((o.owner_key[0], o.owner_key[1], o.ino), None)
            clientid = o.owner_key[0]
            ranges = self.locks.get(o.ino)
            if ranges:
                keep = [r for r in ranges if r[0][0] != clientid]
                if keep:
                    self.locks[o.ino] = keep
                else:
                    self.locks.pop(o.ino, None)
            for other2 in [k for k, ls in self.lock_states.items()
                           if ls.ino == o.ino and ls.owner[0] == clientid]:
                ls = self.lock_states.pop(other2)
                self.lock_by_key.pop((ls.owner[0], ls.owner[1], ls.ino), None)

    # -- byte-range locks --------------------------------------------------
    @staticmethod
    def _range(offset, length):
        if length == 0:
            raise NfsErr(NFS4ERR_INVAL)
        if length == MAX_END:
            return offset, MAX_END
        end = offset + length
        if end > MAX_END:
            raise NfsErr(NFS4ERR_INVAL)
        return offset, end

    def find_conflict(self, ino, owner, offset, length, locktype):
        want_write = locktype in (WRITE_LT, WRITEW_LT)
        start, end = self._range(offset, length)
        with self.lock:
            for r_owner, r_type, r_start, r_end in self.locks.get(ino, ()):
                if r_owner == owner:
                    continue
                if r_start >= end or r_end <= start:
                    continue
                if want_write or r_type in (WRITE_LT, WRITEW_LT):
                    return (r_start, r_end, r_type, r_owner)
        return None

    def lock_range(self, ino, owner, offset, length, locktype):
        """Upsert semantics per RFC 7530: a lock by the same owner replaces
        its own overlapping ranges (up/downgrade), and adjacent or
        overlapping same-type ranges merge into one."""
        start, end = self._range(offset, length)
        ltype = READ_LT if locktype in (READ_LT, READW_LT) else WRITE_LT
        with self.lock:
            segs = []
            for r in self.locks.get(ino, ()):
                r_owner, r_type, r_start, r_end = r
                if r_owner != owner or r_start >= end or r_end <= start:
                    segs.append(r)
                    continue
                if r_start < start:
                    segs.append((r_owner, r_type, r_start, start))
                if r_end > end:
                    segs.append((r_owner, r_type, end, r_end))
            mine = sorted(
                [r for r in segs if r[0] == owner and r[1] == ltype]
                + [(owner, ltype, start, end)],
                key=lambda r: r[2])
            rest = [r for r in segs if not (r[0] == owner and r[1] == ltype)]
            merged = []
            for r in mine:
                if merged and r[2] <= merged[-1][3]:
                    if r[3] > merged[-1][3]:
                        merged[-1] = (owner, ltype, merged[-1][2], r[3])
                else:
                    merged.append(r)
            self.locks[ino] = rest + merged

    def unlock_range(self, ino, owner, offset, length):
        start, end = self._range(offset, length)
        with self.lock:
            out = []
            for r in self.locks.get(ino, ()):
                r_owner, r_type, r_start, r_end = r
                if r_owner != owner or r_start >= end or r_end <= start:
                    out.append(r)
                    continue
                if r_start < start:
                    out.append((r_owner, r_type, r_start, start))
                if r_end > end:
                    out.append((r_owner, r_type, end, r_end))
            if out:
                self.locks[ino] = out
            else:
                self.locks.pop(ino, None)

    def get_lock_state(self, other):
        with self.lock:
            return self.lock_states.get(other)

    def lock_state_for(self, owner, ino):
        key = (owner[0], owner[1], ino)
        with self.lock:
            ls = self.lock_by_key.get(key)
            if ls is None:
                ls = _LockState(self._new_other(), ino, owner)
                self.lock_states[ls.other] = ls
                self.lock_by_key[key] = ls
            return ls

    def release_lockowner(self, owner):
        with self.lock:
            for ranges in self.locks.values():
                if any(r[0] == owner for r in ranges):
                    # RFC 7530: cannot release an owner with locks held
                    raise NfsErr(NFS4ERR_LOCKS_HELD)
            for other in [k for k, ls in self.lock_states.items()
                          if ls.owner == owner]:
                ls = self.lock_states.pop(other)
                self.lock_by_key.pop((ls.owner[0], ls.owner[1], ls.ino), None)
            self.lock_owners.pop(owner, None)


ZERO_STATEID = (0, b"\0" * 12)
ONES_STATEID = (0xFFFFFFFF, b"\xff" * 12)


def unpack_stateid(up):
    seqid = up.uint32()
    other = up.opaque_fixed(12)
    return (seqid, other)


def pack_stateid(pk, seqid, other):
    pk.uint32(seqid)
    pk.opaque_fixed(other)


# ---------------------------------------------------------------------------
# Windows sidecar metadata (uid/gid/mode in an NTFS alternate data stream)
# ---------------------------------------------------------------------------

class SideMeta(object):
    def __init__(self, anon_uid, anon_gid):
        self.anon_uid = anon_uid
        self.anon_gid = anon_gid
        self.cache = {}          # ino -> dict
        self.lock = threading.Lock()

    def read(self, ino, path):
        with self.lock:
            d = self.cache.get(ino)
            if d is not None:
                return d
        d = {}
        try:
            with open(path + SIDE_STREAM, "r", encoding="ascii") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        with self.lock:
            self.cache[ino] = d
        return d

    def update(self, ino, path, **kv):
        d = dict(self.read(ino, path))
        d.update(kv)
        with self.lock:
            self.cache[ino] = d
        try:
            with open(path + SIDE_STREAM, "w", encoding="ascii") as f:
                json.dump(d, f)
        except OSError as e:
            log.debug("sidecar write failed for %s: %s", path, e)

    def forget(self, ino):
        with self.lock:
            self.cache.pop(ino, None)


# ---------------------------------------------------------------------------
# the server
# ---------------------------------------------------------------------------

class Ctx(object):
    __slots__ = ("cfh", "sfh", "uid", "gid", "gids")

    def __init__(self, uid, gid, gids):
        self.cfh = None
        self.sfh = None
        self.uid = uid
        self.gid = gid
        self.gids = gids

    def need_cfh(self):
        if self.cfh is None:
            raise NfsErr(NFS4ERR_NOFILEHANDLE)
        return self.cfh

    def need_sfh(self):
        if self.sfh is None:
            raise NfsErr(NFS4ERR_NOFILEHANDLE)
        return self.sfh


def valid_name(name):
    if name == "":
        raise NfsErr(NFS4ERR_INVAL)
    if len(name.encode("utf-8", "surrogateescape")) > 255:
        raise NfsErr(NFS4ERR_NAMETOOLONG)
    if name in (".", ".."):
        raise NfsErr(NFS4ERR_BADNAME)
    if "/" in name or "\0" in name:
        raise NfsErr(NFS4ERR_BADNAME)
    if IS_WINDOWS and ("\\" in name or ":" in name):
        raise NfsErr(NFS4ERR_BADNAME)
    return name


class NfsServer(object):
    def __init__(self, root, port, read_only=False, lease=90,
                 anon_uid=65534, anon_gid=65534):
        global ATTR_ENCODERS
        if ATTR_ENCODERS is None:
            ATTR_ENCODERS = _build_attr_encoders()
        self.root = root
        self.port = port
        self.read_only = read_only
        self.lease = lease
        self.anon_uid = anon_uid
        self.anon_gid = anon_gid
        self.imap = InodeMap(root)
        self.cache = FileCache()
        self.state = State()
        self.side = SideMeta(anon_uid, anon_gid)
        self.write_verf = os.urandom(8)
        self.symlink_ok = self._probe_symlink()
        self.excl_verfs = {}
        self.ops = self._build_ops()
        self.supported_attrs = sorted(ATTR_ENCODERS) + [
            FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]

    def _probe_symlink(self):
        if not IS_WINDOWS:
            return True
        probe = os.path.join(self.root, ".nfsd-symlink-probe")
        try:
            os.symlink("probe-target", probe)
            os.unlink(probe)
            return True
        except OSError:
            return False

    # -- path helpers ------------------------------------------------------
    def path_of(self, ino):
        return self.imap.path_of(ino)

    def dir_path_of(self, ino):
        """Resolve an inode that must be a directory. A symlink yields
        NFS4ERR_SYMLINK, any other non-directory NFS4ERR_NOTDIR."""
        path = self.path_of(ino)
        st = self.lstat(path)
        if statmod.S_ISLNK(st.st_mode):
            raise NfsErr(NFS4ERR_SYMLINK)
        if not statmod.S_ISDIR(st.st_mode):
            raise NfsErr(NFS4ERR_NOTDIR)
        return path

    def child_path(self, dir_ino, name):
        return os.path.join(self.dir_path_of(dir_ino), valid_name(name))

    def lstat(self, path):
        try:
            return os.lstat(path)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))

    def change_of(self, st):
        # 'change' must move on every content/metadata change. On POSIX
        # ctime does; Windows st_ctime is creation time, so use mtime.
        return st.st_mtime_ns if IS_WINDOWS else max(st.st_ctime_ns, st.st_mtime_ns)

    def dir_cinfo(self, path):
        try:
            st = os.lstat(path)
            return self.change_of(st)
        except OSError:
            return 0

    def fs_stats(self):
        if hasattr(os, "statvfs"):
            v = os.statvfs(self.root)
            fr = v.f_frsize or v.f_bsize or 512
            return {
                "space_total": v.f_blocks * fr,
                "space_free": v.f_bfree * fr,
                "space_avail": v.f_bavail * fr,
                "files_total": v.f_files or (1 << 30),
                "files_free": v.f_ffree or (1 << 30),
                "files_avail": getattr(v, "f_favail", 0) or v.f_ffree or (1 << 30),
            }
        import shutil
        du = shutil.disk_usage(self.root)
        big = 1 << 30
        return {
            "space_total": du.total, "space_free": du.free,
            "space_avail": du.free, "files_total": big,
            "files_free": big, "files_avail": big,
        }

    # -- uid/gid/mode view ---------------------------------------------------
    def file_ugm(self, ino, path, st):
        """Return (uid, gid, mode-bits) for a file."""
        if not IS_WINDOWS:
            return st.st_uid, st.st_gid, statmod.S_IMODE(st.st_mode)
        d = self.side.read(ino, path)
        if statmod.S_ISDIR(st.st_mode):
            synth = 0o755
        elif st.st_mode & statmod.S_IWRITE:
            synth = 0o644
        else:
            synth = 0o444
        return (d.get("uid", self.anon_uid), d.get("gid", self.anon_gid),
                d.get("mode", synth))

    def check_access(self, ctx, st, uid, gid, mode, want_r, want_w, want_x):
        if ctx.uid == 0:
            return True
        if ctx.uid == uid:
            shift = 6
        elif ctx.gid == gid or gid in ctx.gids:
            shift = 3
        else:
            shift = 0
        bits = (mode >> shift) & 7
        if want_r and not bits & 4:
            return False
        if want_w and not bits & 2:
            return False
        if want_x and not bits & 1:
            return False
        return True

    # -- fattr4 encoding -----------------------------------------------------
    def encode_fattr(self, ino, path, st, want):
        """Return fattr4 bytes (bitmap + attrlist) for requested attrs."""
        avail = [a for a in want if a in ATTR_ENCODERS]
        vals = Packer()
        src = _AttrSrc(self, ino, path, st)
        for a in avail:
            ATTR_ENCODERS[a](src, vals)
        pk = Packer()
        pk.raw(pack_bitmap(avail))
        pk.opaque(vals.get())
        return pk.get()

    @staticmethod
    def _decode_settime(up):
        how = up.uint32()
        if how != SET_TO_CLIENT_TIME4:
            return "now"
        sec = up.int64()
        nsec = up.uint32()
        if nsec >= 10**9:
            raise NfsErr(NFS4ERR_INVAL)
        return sec * 10**9 + nsec

    @staticmethod
    def _decode_principal(up):
        s = up.string()
        if s == "":
            raise NfsErr(NFS4ERR_INVAL)
        return parse_owner(s)

    def decode_settable(self, bits, up, for_create=False):
        """Decode attrlist values for SETATTR/OPEN-create. Returns dict."""
        out = {}
        for a in bits:
            if a == FATTR4_SIZE:
                out["size"] = up.uint64()
            elif a == FATTR4_MODE:
                out["mode"] = up.uint32() & 0o7777
            elif a == FATTR4_OWNER:
                out["uid"] = self._decode_principal(up)
            elif a == FATTR4_OWNER_GROUP:
                out["gid"] = self._decode_principal(up)
            elif a == FATTR4_TIME_ACCESS_SET:
                out["atime_ns"] = self._decode_settime(up)
            elif a == FATTR4_TIME_MODIFY_SET:
                out["mtime_ns"] = self._decode_settime(up)
            elif a in ATTR_ENCODERS:
                raise NfsErr(NFS4ERR_INVAL)   # read-only attribute
            else:
                raise NfsErr(NFS4ERR_ATTRNOTSUPP)
        return out

    def apply_attrs(self, ino, path, vals):
        import time as _time
        applied = []
        if self.read_only and vals:
            raise NfsErr(NFS4ERR_ROFS)
        if "size" in vals:
            if vals["size"] > NFS4_INT64_MAX:
                raise NfsErr(NFS4ERR_FBIG)
            e = self.cache.get(ino, path, True)
            try:
                FileCache.ftruncate(e, vals["size"])
            except OverflowError:
                raise NfsErr(NFS4ERR_FBIG)
            applied.append(FATTR4_SIZE)
        if "mode" in vals:
            if IS_WINDOWS:
                self.side.update(ino, path, mode=vals["mode"])
                try:
                    os.chmod(path, vals["mode"])
                except OSError:
                    pass
            else:
                os.chmod(path, vals["mode"])
            applied.append(FATTR4_MODE)
        if "uid" in vals or "gid" in vals:
            uid = vals.get("uid", -1)
            gid = vals.get("gid", -1)
            if IS_WINDOWS:
                kv = {}
                if uid != -1:
                    kv["uid"] = uid
                if gid != -1:
                    kv["gid"] = gid
                self.side.update(ino, path, **kv)
            else:
                os.chown(path, uid, gid)
            if uid != -1:
                applied.append(FATTR4_OWNER)
            if gid != -1:
                applied.append(FATTR4_OWNER_GROUP)
        if "atime_ns" in vals or "mtime_ns" in vals:
            st = self.lstat(path)
            now = _time.time_ns()
            at = vals.get("atime_ns", st.st_atime_ns)
            mt = vals.get("mtime_ns", st.st_mtime_ns)
            if at == "now":
                at = now
            if mt == "now":
                mt = now
            try:
                os.utime(path, ns=(at, mt), follow_symlinks=False)
            except (NotImplementedError, OSError):
                try:
                    os.utime(path, ns=(at, mt))
                except OSError:
                    pass
            if "atime_ns" in vals:
                applied.append(FATTR4_TIME_ACCESS_SET)
            if "mtime_ns" in vals:
                applied.append(FATTR4_TIME_MODIFY_SET)
        return applied

    # -----------------------------------------------------------------------
    # RPC entry point
    # -----------------------------------------------------------------------
    def handle_rpc(self, record):
        up = Unpacker(record)
        try:
            xid = up.uint32()
            mtype = up.uint32()
            if mtype != CALL:
                return None
            rpcvers = up.uint32()
            prog = up.uint32()
            vers = up.uint32()
            proc = up.uint32()
            cred_flavor = up.uint32()
            cred_body = up.opaque(400)
            up.uint32()            # verf flavor
            up.opaque(400)         # verf body
        except XdrError:
            return None

        if rpcvers != RPC_VERS:
            pk = Packer()
            pk.uint32(xid)
            pk.uint32(REPLY)
            pk.uint32(MSG_DENIED)
            pk.uint32(RPC_MISMATCH)
            pk.uint32(RPC_VERS)
            pk.uint32(RPC_VERS)
            return pk.get()

        uid, gid, gids = self.anon_uid, self.anon_gid, []
        if cred_flavor == AUTH_SYS:
            cup = Unpacker(cred_body)
            cup.uint32()                   # stamp
            cup.string(255)                # machinename
            uid = cup.uint32()
            gid = cup.uint32()
            n = cup.uint32()
            if n > 16:
                raise XdrError("too many gids")
            gids = [cup.uint32() for _ in range(n)]
        elif cred_flavor != AUTH_NONE:
            pk = Packer()
            pk.uint32(xid)
            pk.uint32(REPLY)
            pk.uint32(MSG_DENIED)
            pk.uint32(AUTH_ERROR)
            pk.uint32(AUTH_BADCRED)
            return pk.get()

        def accepted(stat_code, body=b""):
            pk = Packer()
            pk.uint32(xid)
            pk.uint32(REPLY)
            pk.uint32(MSG_ACCEPTED)
            pk.uint32(AUTH_NONE)
            pk.uint32(0)
            pk.uint32(stat_code)
            pk.raw(body)
            return pk.get()

        if prog != NFS4_PROGRAM:
            return accepted(PROG_UNAVAIL)
        if vers != NFS_V4:
            pk = Packer()
            pk.uint32(NFS_V4)
            pk.uint32(NFS_V4)
            return accepted(PROG_MISMATCH, pk.get())
        if proc == NFSPROC4_NULL:
            return accepted(SUCCESS)
        if proc != NFSPROC4_COMPOUND:
            return accepted(PROC_UNAVAIL)

        try:
            body = self.compound(up, uid, gid, gids)
        except XdrError as e:
            log.warning("garbage args: %s", e)
            return accepted(GARBAGE_ARGS)
        return accepted(SUCCESS, body)

    # -----------------------------------------------------------------------
    # COMPOUND
    # -----------------------------------------------------------------------
    def compound(self, up, uid, gid, gids):
        tag = up.opaque()
        minor = up.uint32()
        nops = up.uint32()
        if minor != 0:
            pk = Packer()
            pk.uint32(NFS4ERR_MINOR_VERS_MISMATCH)
            pk.opaque(tag)
            pk.uint32(0)
            return pk.get()
        if nops > 4096:
            pk = Packer()
            pk.uint32(NFS4ERR_RESOURCE)
            pk.opaque(tag)
            pk.uint32(0)
            return pk.get()

        ctx = Ctx(uid, gid, gids)
        results = []
        status = NFS4_OK
        for _ in range(nops):
            opnum = up.uint32()
            fn = self.ops.get(opnum)
            if fn is None:
                status = NFS4ERR_OP_ILLEGAL
                rp = Packer()
                rp.uint32(OP_ILLEGAL)
                rp.uint32(status)
                results.append(rp.get())
                break
            try:
                body = fn(ctx, up)
                status = struct.unpack_from(">I", body)[0]
            except NfsErr as e:
                status = e.stat
                body = self._error_body(opnum, status)
            except XdrError:
                # RFC 7530: operation arguments that cannot be decoded
                # yield NFS4ERR_BADXDR for that operation.
                status = NFS4ERR_BADXDR
                body = self._error_body(opnum, status)
            except OverflowError:
                # e.g. offsets/sizes beyond what the OS accepts
                status = NFS4ERR_INVAL
                body = self._error_body(opnum, status)
            except OSError as e:
                status = oserror_to_stat(e)
                body = self._error_body(opnum, status)
            except Exception:
                log.exception("op %s failed", OP_NAMES.get(opnum, opnum))
                status = NFS4ERR_SERVERFAULT
                body = self._error_body(opnum, status)
            rp = Packer()
            rp.uint32(opnum)
            rp.raw(body)
            results.append(rp.get())
            if log.isEnabledFor(logging.DEBUG):
                log.debug("%s -> %s", OP_NAMES.get(opnum, opnum),
                          NFSSTAT4_NAMES.get(status, status))
            if status != NFS4_OK:
                break

        pk = Packer()
        pk.uint32(status)
        pk.opaque(tag)
        pk.uint32(len(results))
        for r in results:
            pk.raw(r)
        return pk.get()

    @staticmethod
    def _error_body(opnum, status):
        pk = Packer()
        pk.uint32(status)
        if opnum == OP_SETATTR:
            pk.uint32(0)     # empty attrsset bitmap
        return pk.get()

    # -----------------------------------------------------------------------
    # op handlers: each decodes its args and returns result bytes
    # (starting with the status u32)
    # -----------------------------------------------------------------------
    def _build_ops(self):
        return {
            OP_ACCESS: self.op_access,
            OP_CLOSE: self.op_close,
            OP_COMMIT: self.op_commit,
            OP_CREATE: self.op_create,
            OP_GETATTR: self.op_getattr,
            OP_GETFH: self.op_getfh,
            OP_LINK: self.op_link,
            OP_LOCK: self.op_lock,
            OP_LOCKT: self.op_lockt,
            OP_LOCKU: self.op_locku,
            OP_LOOKUP: self.op_lookup,
            OP_LOOKUPP: self.op_lookupp,
            OP_NVERIFY: self.op_nverify,
            OP_OPEN: self.op_open,
            OP_OPEN_CONFIRM: self.op_open_confirm,
            OP_OPEN_DOWNGRADE: self.op_open_downgrade,
            OP_PUTFH: self.op_putfh,
            OP_PUTPUBFH: self.op_putrootfh,
            OP_PUTROOTFH: self.op_putrootfh,
            OP_READ: self.op_read,
            OP_READDIR: self.op_readdir,
            OP_READLINK: self.op_readlink,
            OP_REMOVE: self.op_remove,
            OP_RENAME: self.op_rename,
            OP_RENEW: self.op_renew,
            OP_RESTOREFH: self.op_restorefh,
            OP_SAVEFH: self.op_savefh,
            OP_SECINFO: self.op_secinfo,
            OP_SETATTR: self.op_setattr,
            OP_SETCLIENTID: self.op_setclientid,
            OP_SETCLIENTID_CONFIRM: self.op_setclientid_confirm,
            OP_VERIFY: self.op_verify,
            OP_WRITE: self.op_write,
            OP_RELEASE_LOCKOWNER: self.op_release_lockowner,
        }

    def op_access(self, ctx, up):
        want = up.uint32()
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        uid, gid, mode = self.file_ugm(ino, path, st)
        is_dir = statmod.S_ISDIR(st.st_mode)
        r_ok = self.check_access(ctx, st, uid, gid, mode, True, False, False)
        w_ok = self.check_access(ctx, st, uid, gid, mode, False, True, False)
        x_ok = self.check_access(ctx, st, uid, gid, mode, False, False, True)
        if self.read_only:
            w_ok = False
        if is_dir:
            supported = (ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY
                         | ACCESS4_EXTEND | ACCESS4_DELETE)
            access = ((ACCESS4_READ if r_ok else 0)
                      | (ACCESS4_LOOKUP if x_ok else 0)
                      | ((ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE)
                         if w_ok else 0))
        else:
            supported = (ACCESS4_READ | ACCESS4_EXECUTE | ACCESS4_MODIFY
                         | ACCESS4_EXTEND)
            access = ((ACCESS4_READ if r_ok else 0)
                      | (ACCESS4_EXECUTE if x_ok else 0)
                      | ((ACCESS4_MODIFY | ACCESS4_EXTEND) if w_ok else 0))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint32(supported & want)
        pk.uint32(access & want)
        return pk.get()

    def _seqid_dispatch(self, owner, seqid, opnum, work):
        """Run an owner-sequenced op: handle replay, run work(), then commit
        the seqid/reply cache honoring the no-advance error set."""
        disp, cached = self.state.seqid_check(owner, seqid)
        if disp == "replay":
            return cached
        try:
            body = work()
        except NfsErr as e:
            body = self._error_body(opnum, e.stat)
        return self.state.seqid_commit(owner, seqid, body)

    def op_close(self, ctx, up):
        seqid = up.uint32()
        sid = unpack_stateid(up)
        ctx.need_cfh()
        # find the owner even after the open is gone, so a replayed CLOSE
        # (same owner seqid) resolves via the seqid reply cache
        owner_key = self.state.owner_of_other(sid[1])
        if owner_key is None:
            self.state.resolve_stateid(sid)
            raise NfsErr(NFS4ERR_BAD_STATEID)
        owner = self.state.open_owner(*owner_key)

        def work():
            st = self.state.resolve_stateid(sid)      # gen check -> OLD/BAD
            st.gen += 1
            self.state.close_open(st)
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, st.gen, st.other)
            return pk.get()

        return self._seqid_dispatch(owner, seqid, OP_CLOSE, work)

    def _require_regular(self, path):
        """Guard for data ops: opening a FIFO/device would block or fail,
        so refuse non-regular files up front with the spec's errors."""
        st = self.lstat(path)
        if statmod.S_ISDIR(st.st_mode):
            raise NfsErr(NFS4ERR_ISDIR)
        if not statmod.S_ISREG(st.st_mode):
            raise NfsErr(NFS4ERR_INVAL)
        return st

    def op_commit(self, ctx, up):
        up.uint64()                      # offset
        up.uint32()                      # count
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        self._require_regular(path)
        if not self.read_only:
            try:
                e = self.cache.get(ino, path, True)
                FileCache.fsync(e)
            except OSError as err:
                raise NfsErr(oserror_to_stat(err))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque_fixed(self.write_verf)
        return pk.get()

    def op_create(self, ctx, up):
        objtype = up.uint32()
        linkdata = None
        dev_major = dev_minor = 0
        if objtype == NF4LNK:
            linkdata = up.string()
        elif objtype in (NF4BLK, NF4CHR):
            dev_major = up.uint32()
            dev_minor = up.uint32()
        name = up.string()
        bits = unpack_bitmap(up)
        alist = Unpacker(up.opaque())
        vals = self.decode_settable(bits, alist, for_create=True)

        if objtype == NF4REG:
            # regular files are created with OPEN, not CREATE
            raise NfsErr(NFS4ERR_BADTYPE)
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        dir_ino = ctx.need_cfh()
        path = self.child_path(dir_ino, name)
        before = self.dir_cinfo(self.path_of(dir_ino))
        try:
            if objtype == NF4DIR:
                os.mkdir(path, vals.get("mode", 0o755))
            elif objtype == NF4LNK:
                if not self.symlink_ok:
                    raise NfsErr(NFS4ERR_NOTSUPP)
                os.symlink(linkdata, path)
            elif objtype == NF4FIFO and hasattr(os, "mkfifo"):
                os.mkfifo(path, vals.get("mode", 0o644))
            elif objtype == NF4SOCK and hasattr(os, "mknod"):
                os.mknod(path, vals.get("mode", 0o644) | statmod.S_IFSOCK)
            elif objtype in (NF4BLK, NF4CHR) and hasattr(os, "mknod"):
                kind = statmod.S_IFBLK if objtype == NF4BLK else statmod.S_IFCHR
                os.mknod(path, vals.get("mode", 0o644) | kind,
                         os.makedev(dev_major, dev_minor))
            else:
                raise NfsErr(NFS4ERR_NOTSUPP if objtype in
                             (NF4SOCK, NF4BLK, NF4CHR, NF4FIFO)
                             else NFS4ERR_BADTYPE)
        except FileExistsError:
            raise NfsErr(NFS4ERR_EXIST)
        except PermissionError:
            # e.g. unprivileged server refusing to mknod device nodes
            raise NfsErr(NFS4ERR_PERM)
        ino = self.imap.get_or_alloc(dir_ino, name)
        applied = []
        if objtype != NF4LNK and vals:
            try:
                applied = self.apply_attrs(ino, path, vals)
            except OSError:
                pass
        self._chown_new(path, ctx, ino)
        after = self.dir_cinfo(self.path_of(dir_ino))
        ctx.cfh = ino
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(False)
        pk.uint64(before)
        pk.uint64(after)
        pk.raw(pack_bitmap(applied))
        return pk.get()

    def _chown_new(self, path, ctx, ino):
        """Give a newly created object to the caller (best effort)."""
        if IS_WINDOWS:
            self.side.update(ino, path, uid=ctx.uid, gid=ctx.gid)
            return
        try:
            os.lchown(path, ctx.uid, ctx.gid)
        except (OSError, AttributeError):
            pass

    def op_getattr(self, ctx, up):
        want = set(unpack_bitmap(up))
        # write-only attributes may not be requested with GETATTR
        if want & {FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET}:
            raise NfsErr(NFS4ERR_INVAL)
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.raw(self.encode_fattr(ino, path, st, sorted(want)))
        return pk.get()

    def op_getfh(self, ctx, up):
        ino = ctx.need_cfh()
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque(fh_bytes(ino))
        return pk.get()

    def op_link(self, ctx, up):
        name = up.string()
        src_ino = ctx.need_sfh()
        dir_ino = ctx.need_cfh()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        src = self.path_of(src_ino)
        if statmod.S_ISDIR(self.lstat(src).st_mode):
            raise NfsErr(NFS4ERR_ISDIR)   # hard links to directories
        dst = self.child_path(dir_ino, name)
        dpath = self.path_of(dir_ino)
        before = self.dir_cinfo(dpath)
        try:
            os.link(src, dst)
        except FileExistsError:
            raise NfsErr(NFS4ERR_EXIST)
        except (OSError, AttributeError) as e:
            if isinstance(e, OSError):
                raise NfsErr(oserror_to_stat(e))
            raise NfsErr(NFS4ERR_NOTSUPP)
        self.imap.get_or_alloc(dir_ino, name)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(False)
        pk.uint64(before)
        pk.uint64(self.dir_cinfo(dpath))
        return pk.get()

    def _denied_body(self, conflict):
        c_start, c_end, c_type, c_owner = conflict
        pk = Packer()
        pk.uint32(NFS4ERR_DENIED)
        pk.uint64(c_start)
        pk.uint64(MAX_END if c_end == MAX_END else c_end - c_start)
        pk.uint32(c_type)
        pk.uint64(c_owner[0])
        pk.opaque(c_owner[1])
        return pk.get()

    def _lock_type_ok(self, ino):
        lst = self.lstat(self.path_of(ino))
        if statmod.S_ISDIR(lst.st_mode):
            raise NfsErr(NFS4ERR_ISDIR)
        if not statmod.S_ISREG(lst.st_mode):
            raise NfsErr(NFS4ERR_INVAL)

    def _do_lock(self, ino, owner, ls, offset, length, locktype):
        self._lock_type_ok(ino)
        conflict = self.state.find_conflict(ino, owner, offset, length, locktype)
        if conflict is not None:
            return self._denied_body(conflict)
        self.state.lock_range(ino, owner, offset, length, locktype)
        ls.gen += 1
        pk = Packer()
        pk.uint32(NFS4_OK)
        pack_stateid(pk, ls.gen, ls.other)
        return pk.get()

    def op_lock(self, ctx, up):
        locktype = up.uint32()
        up.boolean()                     # reclaim
        offset = up.uint64()
        length = up.uint64()
        new_owner = up.boolean()
        ino = ctx.need_cfh()
        if new_owner:
            open_seqid = up.uint32()
            open_sid = unpack_stateid(up)
            lock_seqid = up.uint32()
            clientid = up.uint64()
            owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
            o = self.state.get_open(open_sid[1])
            if o is None:
                self.state.resolve_stateid(open_sid)
                raise NfsErr(NFS4ERR_BAD_STATEID)
            open_owner = self.state.open_owner(*o.owner_key)
            lowner = (clientid, owner_bytes)

            def work():
                self.state.check_client(clientid)           # LOCK clientid
                self.state.resolve_stateid(open_sid, ino)   # open gen check
                lock_own = self.state.lock_owner(clientid, owner_bytes)
                ls = self.state.lock_state_for(lowner, ino)
                lock_own.seqid = lock_seqid          # establish lock-owner base
                body = self._do_lock(ino, lowner, ls, offset, length, locktype)
                # cache under the lock-owner too (for lock-owner replays)
                self.state.seqid_commit(lock_own, lock_seqid, body)
                return body

            return self._seqid_dispatch(open_owner, open_seqid, OP_LOCK, work)
        else:
            lock_sid = unpack_stateid(up)
            lock_seqid = up.uint32()
            ls0 = self.state.get_lock_state(lock_sid[1])
            if ls0 is None:
                self.state.resolve_stateid(lock_sid)
                raise NfsErr(NFS4ERR_BAD_STATEID)
            lock_own = self.state.lock_owner(*ls0.owner)

            def work():
                ls = self.state.resolve_stateid(lock_sid, ino)
                return self._do_lock(ino, ls0.owner, ls, offset, length,
                                     locktype)

            return self._seqid_dispatch(lock_own, lock_seqid, OP_LOCK, work)

    def op_lockt(self, ctx, up):
        locktype = up.uint32()
        offset = up.uint64()
        length = up.uint64()
        clientid = up.uint64()
        owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
        ino = ctx.need_cfh()
        self.state.check_client(clientid)
        tpath = self.path_of(ino)
        tst = self.lstat(tpath)
        if statmod.S_ISDIR(tst.st_mode):
            raise NfsErr(NFS4ERR_ISDIR)
        if not statmod.S_ISREG(tst.st_mode):
            raise NfsErr(NFS4ERR_INVAL)
        conflict = self.state.find_conflict(
            ino, (clientid, owner_bytes), offset, length, locktype)
        if conflict is not None:
            return self._denied_body(conflict)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_locku(self, ctx, up):
        up.uint32()                      # locktype
        lock_seqid = up.uint32()
        lock_sid = unpack_stateid(up)
        offset = up.uint64()
        length = up.uint64()
        ctx.need_cfh()
        ls0 = self.state.get_lock_state(lock_sid[1])
        if ls0 is None:
            self.state.resolve_stateid(lock_sid)
            raise NfsErr(NFS4ERR_BAD_STATEID)
        lock_own = self.state.lock_owner(*ls0.owner)

        def work():
            ls = self.state.resolve_stateid(lock_sid, ls0.ino)
            self.state.unlock_range(ls.ino, ls.owner, offset, length)
            ls.gen += 1
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, ls.gen, ls.other)
            return pk.get()

        return self._seqid_dispatch(lock_own, lock_seqid, OP_LOCKU, work)

    def op_lookup(self, ctx, up):
        name = up.string()
        dir_ino = ctx.need_cfh()
        path = self.child_path(dir_ino, name)
        dpath = self.path_of(dir_ino)
        dst = self.lstat(dpath)
        d_uid, d_gid, d_mode = self.file_ugm(dir_ino, dpath, dst)
        if not self.check_access(ctx, dst, d_uid, d_gid, d_mode,
                                 False, False, True):
            raise NfsErr(NFS4ERR_ACCESS)   # no search permission on the dir
        if not os.path.lexists(path):
            raise NfsErr(NFS4ERR_NOENT)
        ctx.cfh = self.imap.get_or_alloc(dir_ino, name)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_lookupp(self, ctx, up):
        ino = ctx.need_cfh()
        self.dir_path_of(ino)          # non-directory cfh -> NFS4ERR_NOTDIR
        if ino == ROOT_INO:
            raise NfsErr(NFS4ERR_NOENT)
        ctx.cfh = self.imap.parent_of(ino)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def _verify_common(self, ctx, up):
        bits = unpack_bitmap(up)
        theirs = up.opaque()
        for a in bits:
            if a in (FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET,
                     FATTR4_RDATTR_ERROR):
                raise NfsErr(NFS4ERR_INVAL)
            if a not in ATTR_ENCODERS:
                raise NfsErr(NFS4ERR_ATTRNOTSUPP)
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        vals = Packer()
        src = _AttrSrc(self, ino, path, st)
        for a in bits:
            ATTR_ENCODERS[a](src, vals)
        return vals.get() == theirs

    def op_verify(self, ctx, up):
        same = self._verify_common(ctx, up)
        pk = Packer()
        pk.uint32(NFS4_OK if same else NFS4ERR_NOT_SAME)
        return pk.get()

    def op_nverify(self, ctx, up):
        same = self._verify_common(ctx, up)
        pk = Packer()
        pk.uint32(NFS4ERR_SAME if same else NFS4_OK)
        return pk.get()

    def op_open(self, ctx, up):
        seqid = up.uint32()
        share_access = up.uint32()
        share_deny = up.uint32()
        clientid = up.uint64()
        owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
        opentype = up.uint32()
        createhow = None
        cvals = {}
        cverf = None
        if opentype == OPEN4_CREATE:
            createhow = up.uint32()
            if createhow in (UNCHECKED4, GUARDED4):
                bits = unpack_bitmap(up)
                alist = Unpacker(up.opaque())
                cvals = self.decode_settable(bits, alist, for_create=True)
            else:                          # EXCLUSIVE4
                cverf = up.opaque_fixed(NFS4_VERIFIER_SIZE)
        claim = up.uint32()
        claim_name = None
        if claim == CLAIM_NULL:
            claim_name = up.string()
        owner = self.state.open_owner(clientid, owner_bytes)

        def work():
            if claim != CLAIM_NULL:
                if claim == CLAIM_PREVIOUS:
                    raise NfsErr(NFS4ERR_NO_GRACE)
                raise NfsErr(NFS4ERR_NOTSUPP)
            if share_access & ~OPEN4_SHARE_ACCESS_BOTH or share_access == 0:
                raise NfsErr(NFS4ERR_INVAL)
            if share_deny & ~OPEN4_SHARE_DENY_BOTH:
                raise NfsErr(NFS4ERR_INVAL)
            self.state.check_client(clientid)
            dir_ino = ctx.need_cfh()
            dpath = self.path_of(dir_ino)
            path = self.child_path(dir_ino, claim_name)
            wants_write = bool(share_access & OPEN4_SHARE_ACCESS_WRITE)
            if self.read_only and (wants_write or opentype == OPEN4_CREATE):
                raise NfsErr(NFS4ERR_ROFS)

            before = self.dir_cinfo(dpath)
            applied = []
            if opentype == OPEN4_CREATE:
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
                existed = os.path.lexists(path)
                if createhow == EXCLUSIVE4:
                    ino0 = self.imap.get_child(dir_ino, claim_name)
                    if existed:
                        prev = self.excl_verfs.get(ino0) if ino0 else None
                        if prev != cverf:
                            raise NfsErr(NFS4ERR_EXIST)
                    else:
                        fd = os.open(path, flags | os.O_EXCL, 0o644)
                        os.close(fd)
                        ino0 = self.imap.get_or_alloc(dir_ino, claim_name)
                        self.excl_verfs[ino0] = cverf
                        self._chown_new(path, ctx, ino0)
                else:
                    if createhow == GUARDED4:
                        flags |= os.O_EXCL
                    try:
                        fd = os.open(path, flags, cvals.get("mode", 0o644))
                        os.close(fd)
                    except FileExistsError:
                        raise NfsErr(NFS4ERR_EXIST)
                    ino0 = self.imap.get_or_alloc(dir_ino, claim_name)
                    if not existed:
                        if cvals:
                            try:
                                applied += self.apply_attrs(ino0, path, cvals)
                            except OSError:
                                pass
                        self._chown_new(path, ctx, ino0)
                    elif createhow == UNCHECKED4 and cvals.get("size") == 0:
                        applied += self.apply_attrs(ino0, path, {"size": 0})
            else:
                if not os.path.lexists(path):
                    raise NfsErr(NFS4ERR_NOENT)

            ino = self.imap.get_or_alloc(dir_ino, claim_name)
            st = self.lstat(path)
            if statmod.S_ISDIR(st.st_mode):
                raise NfsErr(NFS4ERR_ISDIR)
            if not statmod.S_ISREG(st.st_mode):
                raise NfsErr(NFS4ERR_SYMLINK)
            if opentype != OPEN4_CREATE:
                uid, gid, mode = self.file_ugm(ino, path, st)
                if not self.check_access(ctx, st, uid, gid, mode,
                                         bool(share_access
                                              & OPEN4_SHARE_ACCESS_READ),
                                         wants_write, False):
                    raise NfsErr(NFS4ERR_ACCESS)
            if self.state.share_conflict(ino, share_access, share_deny,
                                         (clientid, owner_bytes)):
                raise NfsErr(NFS4ERR_SHARE_DENIED)

            o, is_new = self.state.open_file(clientid, owner_bytes, ino,
                                             share_access, share_deny, ctx.uid)
            need_confirm = not owner.confirmed
            if is_new:
                o.confirmed = owner.confirmed
            ctx.cfh = ino
            rflags = OPEN4_RESULT_LOCKTYPE_POSIX
            if need_confirm:
                rflags |= OPEN4_RESULT_CONFIRM
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, o.gen, o.other)
            pk.boolean(False)
            pk.uint64(before)
            pk.uint64(self.dir_cinfo(dpath))
            pk.uint32(rflags)
            pk.raw(pack_bitmap(applied))
            pk.uint32(OPEN_DELEGATE_NONE)
            return pk.get()

        return self._seqid_dispatch(owner, seqid, OP_OPEN, work)

    def op_open_confirm(self, ctx, up):
        sid = unpack_stateid(up)
        seqid = up.uint32()
        ctx.need_cfh()
        o = self.state.get_open(sid[1])
        if o is None:
            self.state.resolve_stateid(sid)
            raise NfsErr(NFS4ERR_BAD_STATEID)
        owner = self.state.open_owner(*o.owner_key)

        def work():
            st = self.state.resolve_stateid(sid)
            if st.confirmed:
                raise NfsErr(NFS4ERR_BAD_STATEID)  # not awaiting confirmation
            st.confirmed = True
            owner.confirmed = True
            st.gen += 1
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, st.gen, st.other)
            return pk.get()

        return self._seqid_dispatch(owner, seqid, OP_OPEN_CONFIRM, work)

    def op_open_downgrade(self, ctx, up):
        sid = unpack_stateid(up)
        seqid = up.uint32()
        access = up.uint32()
        deny = up.uint32()
        ctx.need_cfh()
        o = self.state.get_open(sid[1])
        if o is None:
            self.state.resolve_stateid(sid)
            raise NfsErr(NFS4ERR_BAD_STATEID)
        owner = self.state.open_owner(*o.owner_key)

        def work():
            st = self.state.resolve_stateid(sid)
            # OPEN_DOWNGRADE may only move to a share mode the open-owner has
            # actually held for this file (RFC 7530 sec 15.20); downgrading a
            # single access=BOTH open to READ was never separately opened.
            if access == 0 or (access, deny) not in st.modes:
                raise NfsErr(NFS4ERR_INVAL)
            st.access = access
            st.deny = deny
            st.gen += 1
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, st.gen, st.other)
            return pk.get()

        return self._seqid_dispatch(owner, seqid, OP_OPEN_DOWNGRADE, work)

    def op_putfh(self, ctx, up):
        fh = up.opaque(NFS4_FHSIZE)
        ctx.cfh = fh_ino(fh)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_putrootfh(self, ctx, up):
        ctx.cfh = ROOT_INO
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def _check_stateid_for_io(self, sid, ino, need_write=False):
        """Validate an I/O stateid and enforce share reservations.

        A special (anonymous) stateid is subject to other opens' deny bits
        (NFS4ERR_LOCKED); a real open/lock stateid must match the file and,
        for writes, carry write access (NFS4ERR_OPENMODE). Returns the uid
        that opened the file (or None for a special/lock stateid)."""
        st = self.state.resolve_stateid(sid, ino)
        if st is None:
            if self.state.io_deny_conflict(ino, need_write):
                raise NfsErr(NFS4ERR_LOCKED)
            return None
        acc = getattr(st, "access", None)
        if acc is not None and need_write and not (acc & OPEN4_SHARE_ACCESS_WRITE):
            raise NfsErr(NFS4ERR_OPENMODE)
        return getattr(st, "opener_uid", None)

    def op_read(self, ctx, up):
        sid = unpack_stateid(up)
        offset = up.uint64()
        count = up.uint32()
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        self._require_regular(path)
        self._check_stateid_for_io(sid, ino)
        count = min(count, MAXIO)
        try:
            e = self.cache.get(ino, path, False)
            size = FileCache.size(e)
            if offset >= size:
                # includes absurdly large offsets that os.pread would reject
                data = b""
            else:
                data = FileCache.pread(e, count, offset)
        except OSError as err:
            raise NfsErr(oserror_to_stat(err))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(offset + len(data) >= size)
        pk.opaque(data)
        return pk.get()

    def op_readdir(self, ctx, up):
        cookie = up.uint64()
        up.opaque_fixed(NFS4_VERIFIER_SIZE)   # cookieverf: we use zeros
        dircount = up.uint32()
        maxcount = up.uint32()
        want = sorted(set(unpack_bitmap(up)))
        if set(want) & {FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET}:
            raise NfsErr(NFS4ERR_INVAL)
        dir_ino = ctx.need_cfh()
        dpath = self.dir_path_of(dir_ino)
        dst = self.lstat(dpath)
        d_uid, d_gid, d_mode = self.file_ugm(dir_ino, dpath, dst)
        if not self.check_access(ctx, dst, d_uid, d_gid, d_mode,
                                 True, False, False):
            raise NfsErr(NFS4ERR_ACCESS)     # no read permission on the dir
        if cookie in (1, 2):
            raise NfsErr(NFS4ERR_BAD_COOKIE)
        # even an empty reply needs cookieverf(8) + two booleans
        if maxcount < 16:
            raise NfsErr(NFS4ERR_TOOSMALL)
        try:
            names = sorted(os.listdir(dpath))
        except NotADirectoryError:
            raise NfsErr(NFS4ERR_NOTDIR)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))

        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque_fixed(b"\0" * NFS4_VERIFIER_SIZE)
        body = Packer()
        used = 0
        dused = 0
        eof = True
        emitted = 0
        for i, name in enumerate(names):
            this_cookie = i + 3           # cookies 0,1,2 are reserved
            if this_cookie <= cookie:
                continue
            cpath = os.path.join(dpath, name)
            try:
                st = os.lstat(cpath)
            except OSError:
                continue
            cino = self.imap.get_or_alloc(dir_ino, name)
            ep = Packer()
            ep.boolean(True)
            ep.uint64(this_cookie)
            ep.string(name)
            ep.raw(self.encode_fattr(cino, cpath, st, want))
            eb = ep.get()
            nb = 8 + 4 + len(name)
            if emitted and (used + len(eb) + 8 > maxcount
                            or (dircount and dused + nb > dircount)):
                eof = False
                break
            if not emitted and used + len(eb) + 8 > maxcount:
                raise NfsErr(NFS4ERR_TOOSMALL)
            body.raw(eb)
            used += len(eb)
            dused += nb
            emitted += 1
        body.boolean(False)
        body.boolean(eof)
        pk.raw(body.get())
        return pk.get()

    def op_readlink(self, ctx, up):
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        try:
            target = os.readlink(path)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.string(target)
        return pk.get()

    def op_remove(self, ctx, up):
        name = up.string()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        dir_ino = ctx.need_cfh()
        dpath = self.path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        ino = self.imap.get_child(dir_ino, name)
        if ino:
            self.cache.invalidate(ino)
            self.side.forget(ino)
        before = self.dir_cinfo(dpath)
        try:
            st = os.lstat(path)
            if statmod.S_ISDIR(st.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))
        self.imap.remove_child(dir_ino, name)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(False)
        pk.uint64(before)
        pk.uint64(self.dir_cinfo(dpath))
        return pk.get()

    def op_rename(self, ctx, up):
        oldname = up.string()
        newname = up.string()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        src_dir = ctx.need_sfh()
        dst_dir = ctx.need_cfh()
        spath = self.path_of(src_dir)
        dpath = self.path_of(dst_dir)
        old = self.child_path(src_dir, oldname)
        new = self.child_path(dst_dir, newname)
        moving = self.imap.get_child(src_dir, oldname)
        if moving:
            self.cache.invalidate(moving)
        replaced0 = self.imap.get_child(dst_dir, newname)
        if replaced0:
            self.cache.invalidate(replaced0)
            self.side.forget(replaced0)
        s_before = self.dir_cinfo(spath)
        t_before = self.dir_cinfo(dpath)
        try:
            os.replace(old, new)
        except IsADirectoryError:
            raise NfsErr(NFS4ERR_EXIST)
        except OSError as e:
            # renaming a directory over an existing empty directory
            try:
                if os.path.isdir(old) and os.path.isdir(new):
                    os.rmdir(new)
                    os.rename(old, new)
                else:
                    raise NfsErr(oserror_to_stat(e))
            except OSError as e2:
                raise NfsErr(oserror_to_stat(e2))
        self.imap.move(src_dir, oldname, dst_dir, newname)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(False)
        pk.uint64(s_before)
        pk.uint64(self.dir_cinfo(spath))
        pk.boolean(False)
        pk.uint64(t_before)
        pk.uint64(self.dir_cinfo(dpath))
        return pk.get()

    def op_renew(self, ctx, up):
        clientid = up.uint64()
        self.state.check_client(clientid)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_restorefh(self, ctx, up):
        if ctx.sfh is None:
            raise NfsErr(NFS4ERR_RESTOREFH)
        ctx.cfh = ctx.sfh
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_savefh(self, ctx, up):
        ctx.sfh = ctx.need_cfh()
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_secinfo(self, ctx, up):
        name = up.string()
        dir_ino = ctx.need_cfh()
        path = self.child_path(dir_ino, name)
        if not os.path.lexists(path):
            raise NfsErr(NFS4ERR_NOENT)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint32(2)
        pk.uint32(AUTH_SYS)
        pk.uint32(AUTH_NONE)
        return pk.get()

    def op_setattr(self, ctx, up):
        sid = unpack_stateid(up)
        bits = unpack_bitmap(up)
        alist = Unpacker(up.opaque())
        vals = self.decode_settable(bits, alist)
        if alist.pos != len(alist.data):
            # extraneous bytes after the last decoded attribute
            raise NfsErr(NFS4ERR_BADXDR)
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        if "size" in vals:
            if statmod.S_ISDIR(st.st_mode):
                raise NfsErr(NFS4ERR_ISDIR)
            if not statmod.S_ISREG(st.st_mode):
                raise NfsErr(NFS4ERR_INVAL)
            self._check_stateid_for_io(sid, ino, need_write=True)
        try:
            applied = self.apply_attrs(ino, path, vals)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.raw(pack_bitmap(applied))
        return pk.get()

    def op_setclientid(self, ctx, up):
        verifier = up.opaque_fixed(NFS4_VERIFIER_SIZE)
        owner_id = up.opaque(NFS4_OPAQUE_LIMIT)
        up.uint32()                       # cb_program
        up.string()                       # r_netid
        up.string()                       # r_addr
        up.uint32()                       # callback_ident
        try:
            clientid, confirm = self.state.setclientid(verifier, owner_id, ctx.uid)
        except NfsErr as e:
            if e.stat == NFS4ERR_CLID_INUSE:
                # the CLID_INUSE arm carries the conflicting client's address
                pk = Packer()
                pk.uint32(NFS4ERR_CLID_INUSE)
                pk.string("")             # r_netid
                pk.string("")             # r_addr
                return pk.get()
            raise
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint64(clientid)
        pk.opaque_fixed(confirm)
        return pk.get()

    def op_setclientid_confirm(self, ctx, up):
        clientid = up.uint64()
        confirm = up.opaque_fixed(NFS4_VERIFIER_SIZE)
        self.state.confirm_client(clientid, confirm)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_release_lockowner(self, ctx, up):
        clientid = up.uint64()
        owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
        self.state.release_lockowner((clientid, owner_bytes))
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_write(self, ctx, up):
        sid = unpack_stateid(up)
        offset = up.uint64()
        stable = up.uint32()
        data = up.opaque()
        ino = ctx.need_cfh()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        path = self.path_of(ino)
        st = self._require_regular(path)
        opener = self._check_stateid_for_io(sid, ino, need_write=True)
        if opener is not None and opener != ctx.uid:
            # a different principal is using this open stateid: authorize it
            # against the file's mode (RFC 7530 sec 9.1.6)
            uid, gid, mode = self.file_ugm(ino, path, st)
            if not self.check_access(ctx, st, uid, gid, mode, False, True, False):
                raise NfsErr(NFS4ERR_ACCESS)
        try:
            e = self.cache.get(ino, path, True)
            n = FileCache.pwrite(e, data, offset)
            if stable != UNSTABLE4:
                FileCache.fsync(e)
        except OSError as err:
            raise NfsErr(oserror_to_stat(err))
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint32(n)
        pk.uint32(stable if stable != UNSTABLE4 else UNSTABLE4)
        pk.opaque_fixed(self.write_verf)
        return pk.get()


# ---------------------------------------------------------------------------
# fattr4 attribute encoders (GETATTR / READDIR / VERIFY)
# ---------------------------------------------------------------------------

class _AttrSrc(object):
    __slots__ = ("srv", "ino", "path", "st", "_vfs", "_ugm")

    def __init__(self, srv, ino, path, st):
        self.srv = srv
        self.ino = ino
        self.path = path
        self.st = st
        self._vfs = None
        self._ugm = None

    def vfs(self):
        if self._vfs is None:
            self._vfs = self.srv.fs_stats()
        return self._vfs

    def ugm(self):
        if self._ugm is None:
            self._ugm = self.srv.file_ugm(self.ino, self.path, self.st)
        return self._ugm


def _ftype(st_mode):
    if statmod.S_ISDIR(st_mode):
        return NF4DIR
    if statmod.S_ISLNK(st_mode):
        return NF4LNK
    if statmod.S_ISCHR(st_mode):
        return NF4CHR
    if statmod.S_ISBLK(st_mode):
        return NF4BLK
    if statmod.S_ISFIFO(st_mode):
        return NF4FIFO
    if statmod.S_ISSOCK(st_mode):
        return NF4SOCK
    return NF4REG


def _time3(pk, t_ns):
    sec, ns = divmod(t_ns, 10**9)
    pk.int64(sec)
    pk.uint32(ns)


def parse_owner(s):
    t = s.split("@", 1)[0]
    try:
        return int(t)
    except ValueError:
        return 65534


def _build_attr_encoders():
    enc = {}

    def reg(attr):
        def deco(fn):
            enc[attr] = fn
            return fn
        return deco

    @reg(FATTR4_SUPPORTED_ATTRS)
    def _supported(src, pk):
        pk.raw(pack_bitmap(src.srv.supported_attrs))

    @reg(FATTR4_TYPE)
    def _type(src, pk):
        pk.uint32(_ftype(src.st.st_mode))

    @reg(FATTR4_FH_EXPIRE_TYPE)
    def _fhexp(src, pk):
        pk.uint32(FH4_PERSISTENT)

    @reg(FATTR4_CHANGE)
    def _change(src, pk):
        pk.uint64(src.srv.change_of(src.st))

    @reg(FATTR4_SIZE)
    def _size(src, pk):
        pk.uint64(src.st.st_size)

    @reg(FATTR4_LINK_SUPPORT)
    def _linksup(src, pk):
        pk.boolean(True)

    @reg(FATTR4_SYMLINK_SUPPORT)
    def _symsup(src, pk):
        pk.boolean(src.srv.symlink_ok)

    @reg(FATTR4_NAMED_ATTR)
    def _namedattr(src, pk):
        pk.boolean(False)

    @reg(FATTR4_FSID)
    def _fsid(src, pk):
        pk.uint64(FSID_MAJOR)
        pk.uint64(0)

    @reg(FATTR4_UNIQUE_HANDLES)
    def _uniq(src, pk):
        pk.boolean(True)

    @reg(FATTR4_LEASE_TIME)
    def _lease(src, pk):
        pk.uint32(src.srv.lease)

    @reg(FATTR4_RDATTR_ERROR)
    def _rdattr(src, pk):
        pk.uint32(NFS4_OK)

    @reg(FATTR4_FILEHANDLE)
    def _fh(src, pk):
        pk.opaque(fh_bytes(src.ino))

    @reg(FATTR4_FILEID)
    def _fileid(src, pk):
        pk.uint64(src.ino)

    @reg(FATTR4_FILES_AVAIL)
    def _favail(src, pk):
        pk.uint64(src.vfs()["files_avail"])

    @reg(FATTR4_FILES_FREE)
    def _ffree(src, pk):
        pk.uint64(src.vfs()["files_free"])

    @reg(FATTR4_FILES_TOTAL)
    def _ftotal(src, pk):
        pk.uint64(src.vfs()["files_total"])

    @reg(FATTR4_HOMOGENEOUS)
    def _homog(src, pk):
        pk.boolean(True)

    @reg(FATTR4_MAXFILESIZE)
    def _maxfs(src, pk):
        pk.uint64(NFS4_INT64_MAX)

    @reg(FATTR4_MAXLINK)
    def _maxlink(src, pk):
        pk.uint32(255)

    @reg(FATTR4_MAXNAME)
    def _maxname(src, pk):
        pk.uint32(255)

    @reg(FATTR4_MAXREAD)
    def _maxread(src, pk):
        pk.uint64(MAXIO)

    @reg(FATTR4_MAXWRITE)
    def _maxwrite(src, pk):
        pk.uint64(MAXIO)

    @reg(FATTR4_MODE)
    def _mode(src, pk):
        pk.uint32(src.ugm()[2])

    @reg(FATTR4_NO_TRUNC)
    def _notrunc(src, pk):
        pk.boolean(True)

    @reg(FATTR4_NUMLINKS)
    def _nlink(src, pk):
        pk.uint32(max(1, getattr(src.st, "st_nlink", 1)))

    @reg(FATTR4_OWNER)
    def _owner(src, pk):
        pk.string(str(src.ugm()[0]))

    @reg(FATTR4_OWNER_GROUP)
    def _group(src, pk):
        pk.string(str(src.ugm()[1]))

    @reg(FATTR4_RAWDEV)
    def _rawdev(src, pk):
        rdev = getattr(src.st, "st_rdev", 0) or 0
        if hasattr(os, "major") and rdev:
            pk.uint32(os.major(rdev))
            pk.uint32(os.minor(rdev))
        else:
            pk.uint32(0)
            pk.uint32(0)

    @reg(FATTR4_SPACE_AVAIL)
    def _savail(src, pk):
        pk.uint64(src.vfs()["space_avail"])

    @reg(FATTR4_SPACE_FREE)
    def _sfree(src, pk):
        pk.uint64(src.vfs()["space_free"])

    @reg(FATTR4_SPACE_TOTAL)
    def _stotal(src, pk):
        pk.uint64(src.vfs()["space_total"])

    @reg(FATTR4_SPACE_USED)
    def _sused(src, pk):
        blocks = getattr(src.st, "st_blocks", None)
        pk.uint64(blocks * 512 if blocks is not None else src.st.st_size)

    @reg(FATTR4_TIME_ACCESS)
    def _atime(src, pk):
        _time3(pk, src.st.st_atime_ns)

    @reg(FATTR4_TIME_METADATA)
    def _ctime(src, pk):
        _time3(pk, src.st.st_mtime_ns if IS_WINDOWS else src.st.st_ctime_ns)

    @reg(FATTR4_TIME_MODIFY)
    def _mtime(src, pk):
        _time3(pk, src.st.st_mtime_ns)

    @reg(FATTR4_MOUNTED_ON_FILEID)
    def _mntfileid(src, pk):
        pk.uint64(src.ino)

    @reg(FATTR4_CANSETTIME)
    def _cansettime(src, pk):
        pk.boolean(True)

    @reg(FATTR4_CASE_INSENSITIVE)
    def _caseins(src, pk):
        pk.boolean(IS_WINDOWS)

    @reg(FATTR4_CASE_PRESERVING)
    def _casepres(src, pk):
        pk.boolean(True)

    @reg(FATTR4_CHOWN_RESTRICTED)
    def _chownres(src, pk):
        pk.boolean(not IS_WINDOWS)

    return enc


ATTR_ENCODERS = None  # populated after constants are spliced (see main)


# ---------------------------------------------------------------------------
# TCP transport: RPC record marking (RFC 5531 sec 11)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    parts = []
    got = 0
    while got < n:
        b = sock.recv(min(65536, n - got))
        if not b:
            return None
        parts.append(b)
        got += len(b)
    return b"".join(parts)


def read_record(sock):
    frags = []
    total = 0
    while True:
        hdr = _recv_exact(sock, 4)
        if hdr is None:
            return None
        word = struct.unpack(">I", hdr)[0]
        ln = word & 0x7FFFFFFF
        total += ln
        if total > MAX_RPC_RECORD:
            raise XdrError("rpc record too large")
        if ln:
            body = _recv_exact(sock, ln)
            if body is None:
                return None
            frags.append(body)
        if word & RM_LAST_FRAGMENT:
            return b"".join(frags)


def write_record(sock, data):
    hdr = struct.pack(">I", RM_LAST_FRAGMENT | len(data))
    sock.sendall(hdr + data)


class ConnHandler(socketserver.BaseRequestHandler):
    """Per-connection RPC loop with a small duplicate-request cache (DRC).

    Retransmissions carry the same XID; replaying the cached reply gives the
    exactly-once semantics NFSv4.0 needs for non-idempotent COMPOUNDs over a
    connection (RFC 7530 sec 3.1.1)."""

    DRC_SIZE = 16

    def handle(self):
        sock = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        peer = self.client_address
        log.info("client connected: %s", peer)
        drc = {}          # xid -> reply bytes
        drc_order = []
        try:
            while True:
                rec = read_record(sock)
                if rec is None:
                    break
                xid = struct.unpack_from(">I", rec)[0] if len(rec) >= 4 else None
                if xid is not None and xid in drc:
                    write_record(sock, drc[xid])
                    continue
                reply = self.server.nfs.handle_rpc(rec)
                if reply is None:
                    break
                if xid is not None:
                    drc[xid] = reply
                    drc_order.append(xid)
                    if len(drc_order) > self.DRC_SIZE:
                        drc.pop(drc_order.pop(0), None)
                write_record(sock, reply)
        except (ConnectionError, XdrError) as e:
            log.info("connection %s dropped: %s", peer, e)
        finally:
            log.info("client disconnected: %s", peer)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nfsd.py",
        description="cross-platform user-space NFSv4.0 server (pure Python)")
    ap.add_argument("-dir", required=True, metavar="PATH",
                    help="local directory to export")
    ap.add_argument("-port", type=int, default=2049,
                    help="TCP port to listen on (default 2049)")
    ap.add_argument("-bind", default="0.0.0.0", metavar="ADDR",
                    help="bind address (default 0.0.0.0)")
    ap.add_argument("-ro", action="store_true", help="export read-only")
    ap.add_argument("-lease", type=int, default=90,
                    help="lease time in seconds (default 90)")
    ap.add_argument("-anonuid", type=int, default=65534)
    ap.add_argument("-anongid", type=int, default=65534)
    ap.add_argument("-v", action="count", default=0,
                    help="verbosity (-v info, -vv debug)")
    args = ap.parse_args(argv)

    level = (logging.WARNING, logging.INFO, logging.DEBUG)[min(args.v, 2)]
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname).1s %(name)s: %(message)s")

    root = os.path.realpath(args.dir)
    if not os.path.isdir(root):
        sys.stderr.write("not a directory: %s\n" % root)
        return 2

    if hasattr(os, "umask"):
        os.umask(0)

    nfs = NfsServer(root, args.port, read_only=args.ro, lease=args.lease,
                    anon_uid=args.anonuid, anon_gid=args.anongid)

    srv = Server((args.bind, args.port), ConnHandler,
                 bind_and_activate=False)
    if ":" in args.bind:
        srv.address_family = socket.AF_INET6
        srv.socket = socket.socket(srv.address_family, srv.socket_type)
    srv.server_bind()
    srv.server_activate()
    srv.nfs = nfs

    sys.stdout.write("nfsd.py: exporting %s on port %d (%s)\n"
                     % (root, args.port, "read-only" if args.ro else "read-write"))
    sys.stdout.write("mount with: mount -t nfs -o vers=4.0,port=%d,proto=tcp"
                     " HOST:/ /mnt/x\n" % args.port)
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        nfs.cache.close_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
