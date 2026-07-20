#!/usr/bin/env python3
"""nfsd.py - a cross-platform, user-space NFS server in one pure-Python file.

Exports a single local directory over NFSv3, NFSv4.0, NFSv4.1 and NFSv4.2
on a configurable TCP port. Standard library only (sockets + basic
filesystem operations); no kernel module, no FUSE, no third-party
dependencies. Runs on Linux, Windows, macOS.

Usage:
    python3 nfsd.py -dir /path/to/export -port 2049

Mount (Linux):
    mount -t nfs -o vers=4.2,port=2049,proto=tcp,sec=sys HOST:/ /mnt/x

With -pmap it also answers portmapper v2 queries on port 111 (tcp+udp), so
NFSv3 clients without a mountport= mount option (OpenBSD, NetBSD,
DragonFly) can discover the MOUNT/NFS ports and mount with no port options
at all.

Protocol references:
    RFC 7530 - NFSv4.0 protocol
    RFC 7531 - NFSv4.0 XDR description (constants machine-extracted below)
    RFC 5661/5662 - NFSv4.1 protocol + XDR
    RFC 7862/7863 - NFSv4.2 protocol + XDR (every feature OPTIONAL)
    RFC 1813 - NFSv3 + MOUNT v3
    RFC 1833 - portmapper v2
    RFC 5531 - ONC RPC v2

State model: inode numbers and all NFS state (clients, opens, locks) are
in-memory for the lifetime of the process; after a restart old file handles
return NFS4ERR_STALE. AUTH_SYS and AUTH_NONE only.
"""

import argparse
import base64
import errno
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
#   RFC 5662 (NFSv4.1 XDR)  -> spec/rfc5662.txt (4.1-new names only)
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

# --- RFC 5662 top-level consts (NFSv4.1-new) ---
NFS4_SESSIONID_SIZE = 16
NFS4_MAXFILELEN = 18446744073709551615
NFS4_MAXFILEOFF = 18446744073709551614
ACE4_INHERITED_ACE = 128
ACE4_WRITE_RETENTION = 512
ACE4_WRITE_RETENTION_HOLD = 1024
ACL4_AUTO_INHERIT = 1
ACL4_PROTECTED = 2
ACL4_DEFAULTED = 4
NFS4_DEVICEID4_SIZE = 16
LAYOUT4_RET_REC_FILE = 1
LAYOUT4_RET_REC_FSID = 2
LAYOUT4_RET_REC_ALL = 3
TH4_READ_SIZE = 0
TH4_WRITE_SIZE = 1
TH4_READ_IOSIZE = 2
TH4_WRITE_IOSIZE = 3
RET4_DURATION_INFINITE = 18446744073709551615
FSCHARSET_CAP4_CONTAINS_NON_UTF8 = 1
FSCHARSET_CAP4_ALLOWS_ONLY_UTF8 = 2
FATTR4_SUPPATTR_EXCLCREAT = 75
FATTR4_DIR_NOTIF_DELAY = 56
FATTR4_DIRENT_NOTIF_DELAY = 57
FATTR4_DACL = 58
FATTR4_SACL = 59
FATTR4_CHANGE_POLICY = 60
FATTR4_FS_STATUS = 61
FATTR4_FS_LAYOUT_TYPES = 62
FATTR4_LAYOUT_HINT = 63
FATTR4_LAYOUT_TYPES = 64
FATTR4_LAYOUT_BLKSIZE = 65
FATTR4_LAYOUT_ALIGNMENT = 66
FATTR4_FS_LOCATIONS_INFO = 67
FATTR4_MDSTHRESHOLD = 68
FATTR4_RETENTION_GET = 69
FATTR4_RETENTION_SET = 70
FATTR4_RETENTEVT_GET = 71
FATTR4_RETENTEVT_SET = 72
FATTR4_RETENTION_HOLD = 73
FATTR4_MODE_SET_MASKED = 74
FATTR4_FS_CHARSET_CAP = 76
FSLI4BX_GFLAGS = 0
FSLI4BX_TFLAGS = 1
FSLI4BX_CLSIMUL = 2
FSLI4BX_CLHANDLE = 3
FSLI4BX_CLFILEID = 4
FSLI4BX_CLWRITEVER = 5
FSLI4BX_CLCHANGE = 6
FSLI4BX_CLREADDIR = 7
FSLI4BX_READRANK = 8
FSLI4BX_WRITERANK = 9
FSLI4BX_READORDER = 10
FSLI4BX_WRITEORDER = 11
FSLI4GF_WRITABLE = 1
FSLI4GF_CUR_REQ = 2
FSLI4GF_ABSENT = 4
FSLI4GF_GOING = 8
FSLI4GF_SPLIT = 16
FSLI4TF_RDMA = 1
FSLI4IF_VAR_SUB = 1
NFL4_UFLG_MASK = 63
NFL4_UFLG_DENSE = 1
NFL4_UFLG_COMMIT_THRU_MDS = 2
NFL4_UFLG_STRIPE_UNIT_SIZE_MASK = 4294967232
OPEN4_SHARE_ACCESS_WANT_DELEG_MASK = 65280
OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE = 0
OPEN4_SHARE_ACCESS_WANT_READ_DELEG = 256
OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG = 512
OPEN4_SHARE_ACCESS_WANT_ANY_DELEG = 768
OPEN4_SHARE_ACCESS_WANT_NO_DELEG = 1024
OPEN4_SHARE_ACCESS_WANT_CANCEL = 1280
OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL = 65536
OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED = 131072
OPEN4_RESULT_PRESERVE_UNLINKED = 8
OPEN4_RESULT_MAY_NOTIFY_LOCK = 32
EXCHGID4_FLAG_SUPP_MOVED_REFER = 1
EXCHGID4_FLAG_SUPP_MOVED_MIGR = 2
EXCHGID4_FLAG_BIND_PRINC_STATEID = 256
EXCHGID4_FLAG_USE_NON_PNFS = 65536
EXCHGID4_FLAG_USE_PNFS_MDS = 131072
EXCHGID4_FLAG_USE_PNFS_DS = 262144
EXCHGID4_FLAG_MASK_PNFS = 458752
EXCHGID4_FLAG_UPD_CONFIRMED_REC_A = 1073741824
EXCHGID4_FLAG_CONFIRMED_R = 2147483648
CREATE_SESSION4_FLAG_PERSIST = 1
CREATE_SESSION4_FLAG_CONN_BACK_CHAN = 2
CREATE_SESSION4_FLAG_CONN_RDMA = 4
SEQ4_STATUS_CB_PATH_DOWN = 1
SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING = 2
SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED = 4
SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED = 8
SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED = 16
SEQ4_STATUS_ADMIN_STATE_REVOKED = 32
SEQ4_STATUS_RECALLABLE_STATE_REVOKED = 64
SEQ4_STATUS_LEASE_MOVED = 128
SEQ4_STATUS_RESTART_RECLAIM_NEEDED = 256
SEQ4_STATUS_CB_PATH_DOWN_SESSION = 512
SEQ4_STATUS_BACKCHANNEL_FAULT = 1024
SEQ4_STATUS_DEVID_CHANGED = 2048
SEQ4_STATUS_DEVID_DELETED = 4096
RCA4_TYPE_MASK_RDATA_DLG = 0
RCA4_TYPE_MASK_WDATA_DLG = 1
RCA4_TYPE_MASK_DIR_DLG = 2
RCA4_TYPE_MASK_FILE_LAYOUT = 3
RCA4_TYPE_MASK_BLK_LAYOUT = 4
RCA4_TYPE_MASK_OBJ_LAYOUT_MIN = 8
RCA4_TYPE_MASK_OBJ_LAYOUT_MAX = 9
RCA4_TYPE_MASK_OTHER_LAYOUT_MIN = 12
RCA4_TYPE_MASK_OTHER_LAYOUT_MAX = 15

# --- RFC 5662 enum nfsstat4 (NFSv4.1-new members) ---
NFS4ERR_BADIOMODE = 10049
NFS4ERR_BADLAYOUT = 10050
NFS4ERR_BAD_SESSION_DIGEST = 10051
NFS4ERR_BADSESSION = 10052
NFS4ERR_BADSLOT = 10053
NFS4ERR_COMPLETE_ALREADY = 10054
NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055
NFS4ERR_DELEG_ALREADY_WANTED = 10056
NFS4ERR_BACK_CHAN_BUSY = 10057
NFS4ERR_LAYOUTTRYLATER = 10058
NFS4ERR_LAYOUTUNAVAILABLE = 10059
NFS4ERR_NOMATCHING_LAYOUT = 10060
NFS4ERR_RECALLCONFLICT = 10061
NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062
NFS4ERR_SEQ_MISORDERED = 10063
NFS4ERR_SEQUENCE_POS = 10064
NFS4ERR_REQ_TOO_BIG = 10065
NFS4ERR_REP_TOO_BIG = 10066
NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067
NFS4ERR_RETRY_UNCACHED_REP = 10068
NFS4ERR_UNSAFE_COMPOUND = 10069
NFS4ERR_TOO_MANY_OPS = 10070
NFS4ERR_OP_NOT_IN_SESSION = 10071
NFS4ERR_HASH_ALG_UNSUPP = 10072
NFS4ERR_CLIENTID_BUSY = 10074
NFS4ERR_PNFS_IO_HOLE = 10075
NFS4ERR_SEQ_FALSE_RETRY = 10076
NFS4ERR_BAD_HIGH_SLOT = 10077
NFS4ERR_DEADSESSION = 10078
NFS4ERR_ENCR_ALG_UNSUPP = 10079
NFS4ERR_PNFS_NO_LAYOUT = 10080
NFS4ERR_NOT_ONLY_OP = 10081
NFS4ERR_WRONG_CRED = 10082
NFS4ERR_WRONG_TYPE = 10083
NFS4ERR_DIRDELEG_UNAVAIL = 10084
NFS4ERR_REJECT_DELEG = 10085
NFS4ERR_RETURNCONFLICT = 10086
NFS4ERR_DELEG_REVOKED = 10087

# --- RFC 5662 enum layouttype4 (NFSv4.1-new members) ---
LAYOUT4_NFSV4_1_FILES = 1
LAYOUT4_OSD2_OBJECTS = 2
LAYOUT4_BLOCK_VOLUME = 3

# --- RFC 5662 enum layoutiomode4 (NFSv4.1-new members) ---
LAYOUTIOMODE4_READ = 1
LAYOUTIOMODE4_RW = 2
LAYOUTIOMODE4_ANY = 3

# --- RFC 5662 enum fs4_status_type (NFSv4.1-new members) ---
STATUS4_FIXED = 1
STATUS4_UPDATED = 2
STATUS4_VERSIONED = 3
STATUS4_WRITABLE = 4
STATUS4_REFERRAL = 5

# --- RFC 5662 enum ssv_subkey4 (NFSv4.1-new members) ---
SSV4_SUBKEY_MIC_I2T = 1
SSV4_SUBKEY_MIC_T2I = 2
SSV4_SUBKEY_SEAL_I2T = 3
SSV4_SUBKEY_SEAL_T2I = 4

# --- RFC 5662 enum filelayout_hint_care4 (NFSv4.1-new members) ---
NFLH4_CARE_STRIPE_UNIT_SIZE = 64
NFLH4_CARE_STRIPE_COUNT = 128

# --- RFC 5662 enum createmode4 (NFSv4.1-new members) ---
EXCLUSIVE4_1 = 3

# --- RFC 5662 enum open_delegation_type4 (NFSv4.1-new members) ---
OPEN_DELEGATE_NONE_EXT = 3

# --- RFC 5662 enum open_claim_type4 (NFSv4.1-new members) ---
CLAIM_FH = 4
CLAIM_DELEG_CUR_FH = 5
CLAIM_DELEG_PREV_FH = 6

# --- RFC 5662 enum why_no_delegation4 (NFSv4.1-new members) ---
WND4_NOT_WANTED = 0
WND4_CONTENTION = 1
WND4_RESOURCE = 2
WND4_NOT_SUPP_FTYPE = 3
WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4
WND4_NOT_SUPP_UPGRADE = 5
WND4_NOT_SUPP_DOWNGRADE = 6
WND4_CANCELLED = 7
WND4_IS_DIR = 8

# --- RFC 5662 enum channel_dir_from_client4 (NFSv4.1-new members) ---
CDFC4_FORE = 1
CDFC4_BACK = 2
CDFC4_FORE_OR_BOTH = 3
CDFC4_BACK_OR_BOTH = 7

# --- RFC 5662 enum channel_dir_from_server4 (NFSv4.1-new members) ---
CDFS4_FORE = 1
CDFS4_BACK = 2
CDFS4_BOTH = 3

# --- RFC 5662 enum state_protect_how4 (NFSv4.1-new members) ---
SP4_NONE = 0
SP4_MACH_CRED = 1
SP4_SSV = 2

# --- RFC 5662 enum gddrnf4_status (NFSv4.1-new members) ---
GDD4_OK = 0
GDD4_UNAVAIL = 1

# --- RFC 5662 enum secinfo_style4 (NFSv4.1-new members) ---
SECINFO_STYLE4_CURRENT_FH = 0
SECINFO_STYLE4_PARENT = 1

# --- RFC 5662 enum nfs_opnum4 (NFSv4.1-new members) ---
OP_BACKCHANNEL_CTL = 40
OP_BIND_CONN_TO_SESSION = 41
OP_EXCHANGE_ID = 42
OP_CREATE_SESSION = 43
OP_DESTROY_SESSION = 44
OP_FREE_STATEID = 45
OP_GET_DIR_DELEGATION = 46
OP_GETDEVICEINFO = 47
OP_GETDEVICELIST = 48
OP_LAYOUTCOMMIT = 49
OP_LAYOUTGET = 50
OP_LAYOUTRETURN = 51
OP_SECINFO_NO_NAME = 52
OP_SEQUENCE = 53
OP_SET_SSV = 54
OP_TEST_STATEID = 55
OP_WANT_DELEGATION = 56
OP_DESTROY_CLIENTID = 57
OP_RECLAIM_COMPLETE = 58

# --- RFC 5662 enum notify_type4 (NFSv4.1-new members) ---
NOTIFY4_CHANGE_CHILD_ATTRS = 0
NOTIFY4_CHANGE_DIR_ATTRS = 1
NOTIFY4_REMOVE_ENTRY = 2
NOTIFY4_ADD_ENTRY = 3
NOTIFY4_RENAME_ENTRY = 4
NOTIFY4_CHANGE_COOKIE_VERIFIER = 5

# --- RFC 5662 enum notify_deviceid_type4 (NFSv4.1-new members) ---
NOTIFY_DEVICEID4_CHANGE = 1
NOTIFY_DEVICEID4_DELETE = 2

# --- RFC 5662 enum nfs_cb_opnum4 (NFSv4.1-new members) ---
OP_CB_LAYOUTRECALL = 5
OP_CB_NOTIFY = 6
OP_CB_PUSH_DELEG = 7
OP_CB_RECALL_ANY = 8
OP_CB_RECALLABLE_OBJ_AVAIL = 9
OP_CB_RECALL_SLOT = 10
OP_CB_SEQUENCE = 11
OP_CB_WANTS_CANCELLED = 12
OP_CB_NOTIFY_LOCK = 13
OP_CB_NOTIFY_DEVICEID = 14

# --- RFC 7863 top-level consts (NFSv4.2-new) ---
FATTR4_CLONE_BLKSIZE = 77
FATTR4_SPACE_FREED = 78
FATTR4_CHANGE_ATTR_TYPE = 79
FATTR4_SEC_LABEL = 80
NFL42_UFLG_IO_ADVISE_THRU_MDS = 4
EXCHGID4_FLAG_SUPP_FENCE_OPS = 4

# --- RFC 7863 enum nfsstat4 (NFSv4.2-new members) ---
NFS4ERR_PARTNER_NOTSUPP = 10088
NFS4ERR_PARTNER_NO_AUTH = 10089
NFS4ERR_UNION_NOTSUPP = 10090
NFS4ERR_OFFLOAD_DENIED = 10091
NFS4ERR_WRONG_LFS = 10092
NFS4ERR_BADLABEL = 10093
NFS4ERR_OFFLOAD_NO_REQS = 10094

# --- RFC 7863 enum netloc_type4 (NFSv4.2-new members) ---
NL4_NAME = 1
NL4_URL = 2
NL4_NETADDR = 3

# --- RFC 7863 enum change_attr_type4 (NFSv4.2-new members) ---
NFS4_CHANGE_TYPE_IS_MONOTONIC_INCR = 0
NFS4_CHANGE_TYPE_IS_VERSION_COUNTER = 1
NFS4_CHANGE_TYPE_IS_VERSION_COUNTER_NOPNFS = 2
NFS4_CHANGE_TYPE_IS_TIME_METADATA = 3
NFS4_CHANGE_TYPE_IS_UNDEFINED = 4

# --- RFC 7863 enum data_content4 (NFSv4.2-new members) ---
NFS4_CONTENT_DATA = 0
NFS4_CONTENT_HOLE = 1

# --- RFC 7863 enum nfs_opnum4 (NFSv4.2-new members) ---
OP_ALLOCATE = 59
OP_COPY = 60
OP_COPY_NOTIFY = 61
OP_DEALLOCATE = 62
OP_IO_ADVISE = 63
OP_LAYOUTERROR = 64
OP_LAYOUTSTATS = 65
OP_OFFLOAD_CANCEL = 66
OP_OFFLOAD_STATUS = 67
OP_READ_PLUS = 68
OP_SEEK = 69
OP_WRITE_SAME = 70
OP_CLONE = 71

# --- RFC 7863 enum IO_ADVISE_type4 (NFSv4.2-new members) ---
IO_ADVISE4_NORMAL = 0
IO_ADVISE4_SEQUENTIAL = 1
IO_ADVISE4_SEQUENTIAL_BACKWARDS = 2
IO_ADVISE4_RANDOM = 3
IO_ADVISE4_WILLNEED = 4
IO_ADVISE4_WILLNEED_OPPORTUNISTIC = 5
IO_ADVISE4_DONTNEED = 6
IO_ADVISE4_NOREUSE = 7
IO_ADVISE4_READ = 8
IO_ADVISE4_WRITE = 9
IO_ADVISE4_INIT_PROXIMITY = 10

# --- RFC 7863 enum nfs_cb_opnum4 (NFSv4.2-new members) ---
OP_CB_OFFLOAD = 15

# --- RFC 8276 consts (xattr extension) ---
ACCESS4_XAREAD = 64
ACCESS4_XAWRITE = 128
ACCESS4_XALIST = 256
FATTR4_XATTR_SUPPORT = 82

# --- RFC 8276 enum setxattr_option4 ---
SETXATTR4_EITHER = 0
SETXATTR4_CREATE = 1
SETXATTR4_REPLACE = 2

# --- RFC 8276 additions to enum nfsstat4 / nfs_opnum4 ---
NFS4ERR_NOXATTR = 10095
NFS4ERR_XATTR2BIG = 10096
OP_GETXATTR = 72
OP_SETXATTR = 73
OP_LISTXATTRS = 74
OP_REMOVEXATTR = 75

# --- RFC 1813 sec 2.4 size constants ---
NFS3_FHSIZE = 64
NFS3_COOKIEVERFSIZE = 8
NFS3_CREATEVERFSIZE = 8
NFS3_WRITEVERFSIZE = 8

# --- RFC 1813 top-level consts ---
ACCESS3_READ = 1
ACCESS3_LOOKUP = 2
ACCESS3_MODIFY = 4
ACCESS3_EXTEND = 8
ACCESS3_DELETE = 16
ACCESS3_EXECUTE = 32
FSF3_LINK = 1
FSF3_SYMLINK = 2
FSF3_HOMOGENEOUS = 8
FSF3_CANSETTIME = 16
MNTPATHLEN = 1024
MNTNAMLEN = 255
FHSIZE3 = 64

# --- RFC 1813 enum nfsstat3 ---
NFS3_OK = 0
NFS3ERR_PERM = 1
NFS3ERR_NOENT = 2
NFS3ERR_IO = 5
NFS3ERR_NXIO = 6
NFS3ERR_ACCES = 13
NFS3ERR_EXIST = 17
NFS3ERR_XDEV = 18
NFS3ERR_NODEV = 19
NFS3ERR_NOTDIR = 20
NFS3ERR_ISDIR = 21
NFS3ERR_INVAL = 22
NFS3ERR_FBIG = 27
NFS3ERR_NOSPC = 28
NFS3ERR_ROFS = 30
NFS3ERR_MLINK = 31
NFS3ERR_NAMETOOLONG = 63
NFS3ERR_NOTEMPTY = 66
NFS3ERR_DQUOT = 69
NFS3ERR_STALE = 70
NFS3ERR_REMOTE = 71
NFS3ERR_BADHANDLE = 10001
NFS3ERR_NOT_SYNC = 10002
NFS3ERR_BAD_COOKIE = 10003
NFS3ERR_NOTSUPP = 10004
NFS3ERR_TOOSMALL = 10005
NFS3ERR_SERVERFAULT = 10006
NFS3ERR_BADTYPE = 10007
NFS3ERR_JUKEBOX = 10008

# --- RFC 1813 enum ftype3 ---
NF3REG = 1
NF3DIR = 2
NF3BLK = 3
NF3CHR = 4
NF3LNK = 5
NF3SOCK = 6
NF3FIFO = 7

# --- RFC 1813 enum time_how ---
DONT_CHANGE = 0
SET_TO_SERVER_TIME = 1
SET_TO_CLIENT_TIME = 2

# --- RFC 1813 enum stable_how ---
UNSTABLE = 0
DATA_SYNC = 1
FILE_SYNC = 2

# --- RFC 1813 enum createmode3 ---
UNCHECKED = 0
GUARDED = 1
EXCLUSIVE = 2

# --- RFC 1813 enum mountstat3 ---
MNT3_OK = 0
MNT3ERR_PERM = 1
MNT3ERR_NOENT = 2
MNT3ERR_IO = 5
MNT3ERR_ACCES = 13
MNT3ERR_NOTDIR = 20
MNT3ERR_INVAL = 22
MNT3ERR_NAMETOOLONG = 63
MNT3ERR_NOTSUPP = 10004
MNT3ERR_SERVERFAULT = 10006

# --- RFC 1813 enum nlm4_stats ---
NLM4_GRANTED = 0
NLM4_DENIED = 1
NLM4_DENIED_NOLOCKS = 2
NLM4_BLOCKED = 3
NLM4_DENIED_GRACE_PERIOD = 4
NLM4_DEADLCK = 5
NLM4_ROFS = 6
NLM4_STALE_FH = 7
NLM4_FBIG = 8
NLM4_FAILED = 9

# --- RFC 1813 program declaration: NFS_PROGRAM ---
NFS_PROGRAM = 100003
NFS_V3 = 3
NFSPROC3_NULL = 0
NFSPROC3_GETATTR = 1
NFSPROC3_SETATTR = 2
NFSPROC3_LOOKUP = 3
NFSPROC3_ACCESS = 4
NFSPROC3_READLINK = 5
NFSPROC3_READ = 6
NFSPROC3_WRITE = 7
NFSPROC3_CREATE = 8
NFSPROC3_MKDIR = 9
NFSPROC3_SYMLINK = 10
NFSPROC3_MKNOD = 11
NFSPROC3_REMOVE = 12
NFSPROC3_RMDIR = 13
NFSPROC3_RENAME = 14
NFSPROC3_LINK = 15
NFSPROC3_READDIR = 16
NFSPROC3_READDIRPLUS = 17
NFSPROC3_FSSTAT = 18
NFSPROC3_FSINFO = 19
NFSPROC3_PATHCONF = 20
NFSPROC3_COMMIT = 21

# --- RFC 1813 program declaration: MOUNT_PROGRAM ---
MOUNT_PROGRAM = 100005
MOUNT_V3 = 3
MOUNTPROC3_NULL = 0
MOUNTPROC3_MNT = 1
MOUNTPROC3_DUMP = 2
MOUNTPROC3_UMNT = 3
MOUNTPROC3_UMNTALL = 4
MOUNTPROC3_EXPORT = 5

# --- RFC 1833 portmapper consts ---
PMAP_PORT = 111
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# --- RFC 1833 program declaration: PMAP_PROG ---
PMAP_PROG = 100000
PMAP_VERS = 2
PMAPPROC_NULL = 0
PMAPPROC_SET = 1
PMAPPROC_UNSET = 2
PMAPPROC_GETPORT = 3
PMAPPROC_DUMP = 4
PMAPPROC_CALLIT = 5

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
    10049: 'NFS4ERR_BADIOMODE',
    10050: 'NFS4ERR_BADLAYOUT',
    10051: 'NFS4ERR_BAD_SESSION_DIGEST',
    10052: 'NFS4ERR_BADSESSION',
    10053: 'NFS4ERR_BADSLOT',
    10054: 'NFS4ERR_COMPLETE_ALREADY',
    10055: 'NFS4ERR_CONN_NOT_BOUND_TO_SESSION',
    10056: 'NFS4ERR_DELEG_ALREADY_WANTED',
    10057: 'NFS4ERR_BACK_CHAN_BUSY',
    10058: 'NFS4ERR_LAYOUTTRYLATER',
    10059: 'NFS4ERR_LAYOUTUNAVAILABLE',
    10060: 'NFS4ERR_NOMATCHING_LAYOUT',
    10061: 'NFS4ERR_RECALLCONFLICT',
    10062: 'NFS4ERR_UNKNOWN_LAYOUTTYPE',
    10063: 'NFS4ERR_SEQ_MISORDERED',
    10064: 'NFS4ERR_SEQUENCE_POS',
    10065: 'NFS4ERR_REQ_TOO_BIG',
    10066: 'NFS4ERR_REP_TOO_BIG',
    10067: 'NFS4ERR_REP_TOO_BIG_TO_CACHE',
    10068: 'NFS4ERR_RETRY_UNCACHED_REP',
    10069: 'NFS4ERR_UNSAFE_COMPOUND',
    10070: 'NFS4ERR_TOO_MANY_OPS',
    10071: 'NFS4ERR_OP_NOT_IN_SESSION',
    10072: 'NFS4ERR_HASH_ALG_UNSUPP',
    10074: 'NFS4ERR_CLIENTID_BUSY',
    10075: 'NFS4ERR_PNFS_IO_HOLE',
    10076: 'NFS4ERR_SEQ_FALSE_RETRY',
    10077: 'NFS4ERR_BAD_HIGH_SLOT',
    10078: 'NFS4ERR_DEADSESSION',
    10079: 'NFS4ERR_ENCR_ALG_UNSUPP',
    10080: 'NFS4ERR_PNFS_NO_LAYOUT',
    10081: 'NFS4ERR_NOT_ONLY_OP',
    10082: 'NFS4ERR_WRONG_CRED',
    10083: 'NFS4ERR_WRONG_TYPE',
    10084: 'NFS4ERR_DIRDELEG_UNAVAIL',
    10085: 'NFS4ERR_REJECT_DELEG',
    10086: 'NFS4ERR_RETURNCONFLICT',
    10087: 'NFS4ERR_DELEG_REVOKED',
    10088: 'NFS4ERR_PARTNER_NOTSUPP',
    10089: 'NFS4ERR_PARTNER_NO_AUTH',
    10090: 'NFS4ERR_UNION_NOTSUPP',
    10091: 'NFS4ERR_OFFLOAD_DENIED',
    10092: 'NFS4ERR_WRONG_LFS',
    10093: 'NFS4ERR_BADLABEL',
    10094: 'NFS4ERR_OFFLOAD_NO_REQS',
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
    40: 'OP_BACKCHANNEL_CTL',
    41: 'OP_BIND_CONN_TO_SESSION',
    42: 'OP_EXCHANGE_ID',
    43: 'OP_CREATE_SESSION',
    44: 'OP_DESTROY_SESSION',
    45: 'OP_FREE_STATEID',
    46: 'OP_GET_DIR_DELEGATION',
    47: 'OP_GETDEVICEINFO',
    48: 'OP_GETDEVICELIST',
    49: 'OP_LAYOUTCOMMIT',
    50: 'OP_LAYOUTGET',
    51: 'OP_LAYOUTRETURN',
    52: 'OP_SECINFO_NO_NAME',
    53: 'OP_SEQUENCE',
    54: 'OP_SET_SSV',
    55: 'OP_TEST_STATEID',
    56: 'OP_WANT_DELEGATION',
    57: 'OP_DESTROY_CLIENTID',
    58: 'OP_RECLAIM_COMPLETE',
    59: 'OP_ALLOCATE',
    60: 'OP_COPY',
    61: 'OP_COPY_NOTIFY',
    62: 'OP_DEALLOCATE',
    63: 'OP_IO_ADVISE',
    64: 'OP_LAYOUTERROR',
    65: 'OP_LAYOUTSTATS',
    66: 'OP_OFFLOAD_CANCEL',
    67: 'OP_OFFLOAD_STATUS',
    68: 'OP_READ_PLUS',
    69: 'OP_SEEK',
    70: 'OP_WRITE_SAME',
    71: 'OP_CLONE',
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
MAX_SESSION_SLOTS = 64       # NFSv4.1 fore-channel slot table cap per session
SLOT_CACHE_LIMIT = 262144    # cache session replies up to this size for replay
MAXIO_UDP = 32768            # NFSv3-over-UDP rtmax/wtmax: a whole READ reply
                             # must fit one 64 KiB datagram with headers
UDP_DRC_SIZE = 512           # cached (addr, xid) replies for UDP retransmits


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


# Linux fallocate(2) flags for real hole punching (uapi/linux/falloc.h);
# libc is loaded lazily and only on Linux -- everywhere else the caller
# falls back to writing zeros.
FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02
_LIBC = None


def _punch_hole_linux(fd, off, length):
    """Punch a real hole with fallocate(2). True if the hole was punched."""
    global _LIBC
    if not sys.platform.startswith("linux"):
        return False
    if _LIBC is None:
        try:
            import ctypes
            import ctypes.util
            lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                              use_errno=True)
            lib.fallocate.argtypes = [ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int64, ctypes.c_int64]
            lib.fallocate.restype = ctypes.c_int
            _LIBC = lib
        except Exception:
            _LIBC = False
    if not _LIBC:
        return False
    mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
    return _LIBC.fallocate(fd, mode, off, length) == 0


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

    @staticmethod
    def lseek(e, off, whence):
        """Sparse-file seek for NFSv4.2 SEEK. Needs SEEK_DATA/SEEK_HOLE
        (Linux 3.1+, Solaris); the caller handles their absence."""
        with e.lock:
            return os.lseek(e.fd, off, whence)

    @staticmethod
    def fallocate(e, off, length):
        """Reserve backing blocks for [off, off+length) (NFSv4.2 ALLOCATE).

        os.posix_fallocate is Linux/BSD-only. Elsewhere, extend the file if
        the region lies past EOF -- the size effect ALLOCATE promises (RFC
        7862 sec 15.1.3) without the space reservation."""
        if hasattr(os, "posix_fallocate"):
            with e.lock:
                os.posix_fallocate(e.fd, off, length)
            return
        with e.lock:
            if off + length > os.fstat(e.fd).st_size:
                os.ftruncate(e.fd, off + length)

    @staticmethod
    def punch_hole(e, off, length):
        """Unreserve [off, off+length), reading back as zeros (NFSv4.2
        DEALLOCATE). Real hole punching needs Linux fallocate(2) flags via
        ctypes; the portable fallback writes zeros, which keeps the READ
        semantics the spec requires while not freeing the blocks."""
        with e.lock:
            size = os.fstat(e.fd).st_size
            if off >= size:
                return
            length = min(length, size - off)
            if _punch_hole_linux(e.fd, off, length):
                return
            zeros = b"\0" * min(length, 1 << 20)
            done = 0
            while done < length:
                n = min(len(zeros), length - done)
                if hasattr(os, "pwrite"):
                    done += os.pwrite(e.fd, zeros[:n], off + done)
                else:
                    os.lseek(e.fd, off + done, os.SEEK_SET)
                    done += os.write(e.fd, zeros[:n])


# ---------------------------------------------------------------------------
# NFSv4 state: clients, opens, byte-range locks (all in-memory)
# ---------------------------------------------------------------------------

SEQID_NO_ADV = frozenset([
    NFS4ERR_STALE_CLIENTID, NFS4ERR_STALE_STATEID, NFS4ERR_BAD_STATEID,
    NFS4ERR_BAD_SEQID, NFS4ERR_BADXDR, NFS4ERR_RESOURCE, NFS4ERR_NOFILEHANDLE,
])


class _Client(object):
    __slots__ = ("clientid", "verifier", "owner_id", "confirm", "confirmed",
                 "last_renew", "principal", "eir_seq", "cs_replay",
                 "sessions_n", "reclaim_done")

    def __init__(self, clientid, verifier, owner_id, confirm, principal):
        self.clientid = clientid
        self.verifier = verifier
        self.owner_id = owner_id
        self.confirm = confirm
        self.confirmed = False
        self.last_renew = time.monotonic()
        self.principal = principal
        # NFSv4.1 (RFC 5661): EXCHANGE_ID/CREATE_SESSION bookkeeping
        self.eir_seq = 1          # sequenceid expected in next CREATE_SESSION
        self.cs_replay = None     # (csa_sequence, body) cached CREATE_SESSION
        self.sessions_n = 0       # live sessions (DESTROY_CLIENTID busy check)
        self.reclaim_done = False # RECLAIM_COMPLETE seen (COMPLETE_ALREADY)


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


class _Slot(object):
    """One NFSv4.1 session slot: at-most-once execution + reply cache.

    seqid is the last sa_sequenceid accepted on this slot (0 = never used;
    RFC 5661 sec 18.46.1: the first use of a slot carries sequenceid 1).
    reply holds the full cached COMPOUND reply, or None when the reply was
    too large to cache (filled distinguishes that from a never-used slot)."""
    __slots__ = ("seqid", "reply", "filled")

    def __init__(self):
        self.seqid = 0
        self.reply = None
        self.filled = False


class _Session(object):
    __slots__ = ("sessionid", "clientid", "slots", "maxreq", "maxresp",
                 "maxresp_cached", "maxops")

    def __init__(self, sessionid, clientid, nslots, maxreq, maxresp,
                 maxresp_cached, maxops):
        self.sessionid = sessionid
        self.clientid = clientid
        self.slots = [_Slot() for _ in range(nslots)]
        # negotiated fore-channel limits, enforced per compound
        self.maxreq = maxreq
        self.maxresp = maxresp
        self.maxresp_cached = maxresp_cached
        self.maxops = maxops


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
        self.sessions = {}          # sessionid (16 bytes) -> _Session
        self.next_session = 1

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

    def _expire_if_dead_locked(self, clientid):
        """Courteous server (RFC 7530 sec 9.6.3): keep an expired client's
        state around until it actually blocks someone else, then reap it.
        Returns True if the client's lease had run out and it was purged."""
        c = self.clients.get(clientid)
        if c is not None and time.monotonic() - c.last_renew <= self.lease:
            return False
        self._purge_client_locked(clientid)
        return True

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

    # -- NFSv4.1 client / session lifecycle (RFC 5661 sec 18.35/18.36) ----
    def _drop_client_locked(self, clientid):
        """Remove a client record with all its state and sessions."""
        c = self.clients.pop(clientid, None)
        if c is not None and self.by_owner_id.get(c.owner_id) == clientid:
            self.by_owner_id.pop(c.owner_id, None)
        self._purge_client_locked(clientid)
        for sid in [k for k, s in self.sessions.items()
                    if s.clientid == clientid]:
            self.sessions.pop(sid, None)

    def exchange_id(self, verifier, owner_id, principal, update=False):
        """EXCHANGE_ID: return (clientid, eir_sequenceid, confirmed).

        Implements the client-record case analysis of RFC 5661 sec 18.35.4
        (cases 1-9)."""
        with self.lock:
            cur_id = self.by_owner_id.get(owner_id)
            cur = self.clients.get(cur_id) if cur_id else None
            if update:
                if cur is None:
                    raise NfsErr(NFS4ERR_NOENT)       # case 7: no confirmed
                if cur.verifier != verifier:
                    raise NfsErr(NFS4ERR_NOT_SAME)    # case 8: wrong verifier
                if cur.principal != principal:
                    raise NfsErr(NFS4ERR_PERM)        # case 9: wrong principal
                cur.last_renew = time.monotonic()     # case 6: update
                return cur.clientid, cur.eir_seq, True
            if cur is not None:
                if cur.principal != principal:
                    # case 3: client collision. With live state the owner id
                    # stays taken; otherwise the old record is dropped.
                    if (self._client_has_state(cur.clientid)
                            and time.monotonic() - cur.last_renew
                            <= self.lease):
                        raise NfsErr(NFS4ERR_CLID_INUSE)
                    self._drop_client_locked(cur.clientid)
                elif cur.verifier == verifier:
                    # case 2: retry / trunking probe -> same record
                    cur.last_renew = time.monotonic()
                    return cur.clientid, cur.eir_seq, True
                # else case 5 (client restart): keep the confirmed record;
                # it is displaced when CREATE_SESSION confirms the new one
            # cases 1 and 4: replace any unconfirmed record for this owner
            for cid in [k for k, c in self.clients.items()
                        if c.owner_id == owner_id and not c.confirmed]:
                self.clients.pop(cid, None)
            clientid = self.next_clientid
            self.next_clientid += 1
            c = _Client(clientid, verifier, owner_id, os.urandom(8), principal)
            self.clients[clientid] = c
            return clientid, c.eir_seq, False

    def _new_sessionid(self):
        n = self.next_session
        self.next_session += 1
        return struct.pack(">IQI", self.boot_epoch, n, 0)

    def create_session(self, clientid, seq, principal, make_session):
        """CREATE_SESSION: exactly-once via the client's eir_seq;
        make_session(clientid) builds the session + resok body, which is
        cached for replay."""
        with self.lock:
            c = self.clients.get(clientid)
            if c is None:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if not c.confirmed and (time.monotonic() - c.last_renew
                                    > self.lease):
                # RFC 5661 sec 18.35.4: unconfirmed records not confirmed
                # within a lease period SHOULD be removed
                self.clients.pop(clientid, None)
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if c.cs_replay is not None and seq == c.cs_replay[0]:
                return c.cs_replay[1]
            if seq != c.eir_seq:
                raise NfsErr(NFS4ERR_SEQ_MISORDERED)
            if not c.confirmed and c.principal != principal:
                # RFC 5661 sec 18.36.4 case 4: only the principal that
                # created the unconfirmed client ID may confirm it
                raise NfsErr(NFS4ERR_CLID_INUSE)
            sess, body = make_session(clientid)
            if not c.confirmed:
                prev = self.by_owner_id.get(c.owner_id)
                if prev is not None and prev != clientid:
                    self._drop_client_locked(prev)
                c.confirmed = True
                self.by_owner_id[c.owner_id] = clientid
            self.sessions[sess.sessionid] = sess
            c.sessions_n += 1
            c.last_renew = time.monotonic()
            c.cs_replay = (seq, body)
            c.eir_seq = (seq + 1) & 0xFFFFFFFF
            return body

    def sequence(self, sessionid, seqid, slotid):
        """SEQUENCE slot logic: ('replay', bytes_or_None, sess, slot) for a
        retransmission (bytes None = reply was not cached), or
        ('process', sess, slot). Renews the client's lease."""
        with self.lock:
            sess = self.sessions.get(sessionid)
            if sess is None:
                raise NfsErr(NFS4ERR_BADSESSION)
            if slotid >= len(sess.slots):
                raise NfsErr(NFS4ERR_BADSLOT)
            slot = sess.slots[slotid]
            if seqid == slot.seqid and slot.filled:
                return ("replay", slot.reply, sess, slot)
            if seqid != ((slot.seqid + 1) & 0xFFFFFFFF):
                raise NfsErr(NFS4ERR_SEQ_MISORDERED)
            slot.seqid = seqid
            slot.reply = None
            slot.filled = False
            c = self.clients.get(sess.clientid)
            if c is not None:
                c.last_renew = time.monotonic()
            return ("process", sess, slot)

    def slot_store(self, slot, reply):
        with self.lock:
            slot.reply = reply if len(reply) <= SLOT_CACHE_LIMIT else None
            slot.filled = True

    def find_session(self, sessionid):
        with self.lock:
            sess = self.sessions.get(sessionid)
            if sess is None:
                raise NfsErr(NFS4ERR_BADSESSION)
            return sess

    def destroy_session(self, sessionid):
        with self.lock:
            sess = self.sessions.pop(sessionid, None)
            if sess is None:
                raise NfsErr(NFS4ERR_BADSESSION)
            c = self.clients.get(sess.clientid)
            if c is not None and c.sessions_n > 0:
                c.sessions_n -= 1

    def destroy_clientid(self, clientid):
        with self.lock:
            c = self.clients.get(clientid)
            if c is None:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if c.sessions_n > 0 or self._client_has_state(clientid):
                raise NfsErr(NFS4ERR_CLIENTID_BUSY)
            self.clients.pop(clientid, None)
            if self.by_owner_id.get(c.owner_id) == clientid:
                self.by_owner_id.pop(c.owner_id, None)

    def reclaim_complete(self, clientid, one_fs):
        with self.lock:
            c = self.clients.get(clientid)
            if c is None:
                raise NfsErr(NFS4ERR_STALE_CLIENTID)
            if not one_fs:
                if c.reclaim_done:
                    raise NfsErr(NFS4ERR_COMPLETE_ALREADY)
                c.reclaim_done = True

    def check_reclaim_done(self, clientid):
        """RFC 5661 sec 18.51.3: a 4.1 client must send RECLAIM_COMPLETE
        before its first non-reclaim locking operation, else GRACE."""
        with self.lock:
            c = self.clients.get(clientid)
            if c is not None and not c.reclaim_done:
                raise NfsErr(NFS4ERR_GRACE)

    def free_stateid(self, sid):
        """FREE_STATEID (RFC 5661 sec 18.38): lock stateids with no locks
        held, or revoked/expired stateids; opens raise LOCKS_HELD."""
        other = sid[1]
        with self.lock:
            ls = self.lock_states.get(other)
            if ls is not None:
                held = [r for r in self.locks.get(ls.ino, ())
                        if r[0] == ls.owner]
                if held:
                    raise NfsErr(NFS4ERR_LOCKS_HELD)
                self.lock_states.pop(other, None)
                self.lock_by_key.pop((ls.owner[0], ls.owner[1], ls.ino), None)
                return
            if other in self.opens:
                raise NfsErr(NFS4ERR_LOCKS_HELD)
            if other in self.expired:
                self.expired.discard(other)
                return
        # unknown: surface STALE/BAD via the common resolution path
        self.resolve_stateid(sid)
        raise NfsErr(NFS4ERR_BAD_STATEID)

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
            while True:
                for o in self.opens.values():
                    if o.ino != ino:
                        continue
                    if (access & o.deny) or (deny & o.access):
                        if self._expire_if_dead_locked(o.owner_key[0]):
                            break    # purge mutated self.opens: rescan
                        return True
                else:
                    return False

    def io_deny_conflict(self, ino, writing):
        """True if an anonymous READ/WRITE is blocked by some open's deny."""
        want = OPEN4_SHARE_DENY_WRITE if writing else OPEN4_SHARE_DENY_READ
        with self.lock:
            while True:
                for o in self.opens.values():
                    if o.ino == ino and (o.deny & want):
                        if self._expire_if_dead_locked(o.owner_key[0]):
                            break    # purge mutated self.opens: rescan
                        return True
                else:
                    return False

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
            while True:
                for r_owner, r_type, r_start, r_end in self.locks.get(ino, ()):
                    if r_owner == owner:
                        continue
                    if r_start >= end or r_end <= start:
                        continue
                    if want_write or r_type in (WRITE_LT, WRITEW_LT):
                        if self._expire_if_dead_locked(r_owner[0]):
                            break    # purge mutated self.locks: rescan
                        return (r_start, r_end, r_type, r_owner)
                else:
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
# NFSv4.1 "use the current stateid" special value (RFC 5661 sec 16.2.3.1.2)
CURRENT_SID = (1, b"\0" * 12)


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
# extended attributes (RFC 8276): the platform's own xattrs on POSIX, the
# sidecar JSON on Windows
# ---------------------------------------------------------------------------

# The wire name is mapped into the OS "user." namespace: RFC 8276 sec 3
# covers "user-managed metadata only", and that is also the only namespace
# an unprivileged POSIX server may write. The Linux NFS server does the
# same, so a client's `setfattr -n user.foo` lands on user.foo here.
XATTR_NS = "user."
XATTR_VALUE_MAX = 65536          # larger values get NFS4ERR_XATTR2BIG

# Darwin xattr flags (man 2 setxattr)
_MAC_XATTR_CREATE = 0x0002
_MAC_XATTR_REPLACE = 0x0004
_MAC_LIBC = None


def _mac_xattr_libc():
    """libc bound for Darwin's xattr calls, or None off Darwin.

    CPython exposes os.getxattr and friends on Linux only, but Darwin has
    the same calls with an extra (position, options) pair, so ctypes gets
    macOS the same functionality.
    """
    global _MAC_LIBC
    if _MAC_LIBC is None:
        if sys.platform != "darwin":
            _MAC_LIBC = False
            return None
        try:
            import ctypes
            import ctypes.util
            lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib",
                              use_errno=True)
            cc, cv, cs = ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t
            lib.getxattr.argtypes = [cc, cc, cv, cs, ctypes.c_uint32,
                                     ctypes.c_int]
            lib.getxattr.restype = ctypes.c_ssize_t
            lib.setxattr.argtypes = [cc, cc, cv, cs, ctypes.c_uint32,
                                     ctypes.c_int]
            lib.setxattr.restype = ctypes.c_int
            lib.listxattr.argtypes = [cc, cv, cs, ctypes.c_int]
            lib.listxattr.restype = ctypes.c_ssize_t
            lib.removexattr.argtypes = [cc, cc, ctypes.c_int]
            lib.removexattr.restype = ctypes.c_int
            _MAC_LIBC = lib
        except Exception:
            _MAC_LIBC = False
    return _MAC_LIBC or None


class XattrStore(object):
    """Backing store for GETXATTR/SETXATTR/LISTXATTRS/REMOVEXATTR.

    POSIX: os.*xattr on the file. Windows: a dict inside the sidecar
    stream that already carries uid/gid/mode, values base64-encoded so the
    sidecar stays plain ASCII JSON."""

    def __init__(self, side):
        self.side = side
        self.posix = hasattr(os, "getxattr")     # Linux: os.*xattr
        self.mac = None if self.posix else _mac_xattr_libc()

    def supported(self, path):
        """Whether this export can store xattrs (fattr4_xattr_support)."""
        if self.posix:
            try:
                os.listxattr(path)
                return True
            except OSError:
                return False
        if self.mac:
            return self._mac_call(
                self.mac.listxattr, os.fsencode(path), None, 0, 0,
                probe=True) is not None
        return IS_WINDOWS

    def _mac_call(self, fn, *args, **kw):
        """Run a Darwin xattr call, raising NfsErr on failure. probe=True
        returns None instead of raising (capability probing)."""
        import ctypes
        ctypes.set_errno(0)
        rc = fn(*args)
        if rc < 0:
            e = OSError(ctypes.get_errno(), "xattr")
            if kw.get("probe"):
                return None
            raise self._map_err(e)
        return rc

    def _mac_get(self, path, name):
        p, n = os.fsencode(path), name.encode("utf-8")
        size = self._mac_call(self.mac.getxattr, p, n, None, 0, 0, 0)
        if size == 0:
            return b""
        import ctypes
        buf = ctypes.create_string_buffer(size)
        got = self._mac_call(self.mac.getxattr, p, n, buf, size, 0, 0)
        return buf.raw[:got]

    def _mac_list(self, path):
        p = os.fsencode(path)
        size = self._mac_call(self.mac.listxattr, p, None, 0, 0)
        if size == 0:
            return []
        import ctypes
        buf = ctypes.create_string_buffer(size)
        got = self._mac_call(self.mac.listxattr, p, buf, size, 0)
        return [n.decode("utf-8", "surrogateescape")
                for n in buf.raw[:got].split(b"\0") if n]

    @staticmethod
    def _osname(name):
        return XATTR_NS + name

    def _sidecar_map(self, ino, path):
        return dict(self.side.read(ino, path).get("xattrs", {}))

    def get(self, ino, path, name):
        if self.posix:
            try:
                return os.getxattr(path, self._osname(name))
            except OSError as e:
                raise self._map_err(e)
        if self.mac:
            return self._mac_get(path, self._osname(name))
        m = self._sidecar_map(ino, path)
        if name not in m:
            raise NfsErr(NFS4ERR_NOXATTR)
        return base64.b64decode(m[name])

    def set(self, ino, path, name, value, option):
        if len(value) > XATTR_VALUE_MAX:
            raise NfsErr(NFS4ERR_XATTR2BIG)
        if self.posix:
            flags = 0
            if option == SETXATTR4_CREATE:
                flags = os.XATTR_CREATE
            elif option == SETXATTR4_REPLACE:
                flags = os.XATTR_REPLACE
            try:
                os.setxattr(path, self._osname(name), value, flags)
            except OSError as e:
                raise self._map_err(e)
            return
        if self.mac:
            flags = 0
            if option == SETXATTR4_CREATE:
                flags = _MAC_XATTR_CREATE
            elif option == SETXATTR4_REPLACE:
                flags = _MAC_XATTR_REPLACE
            self._mac_call(self.mac.setxattr, os.fsencode(path),
                           self._osname(name).encode("utf-8"),
                           value, len(value), 0, flags)
            return
        m = self._sidecar_map(ino, path)
        if option == SETXATTR4_CREATE and name in m:
            raise NfsErr(NFS4ERR_EXIST)
        if option == SETXATTR4_REPLACE and name not in m:
            raise NfsErr(NFS4ERR_NOXATTR)
        m[name] = base64.b64encode(value).decode("ascii")
        self.side.update(ino, path, xattrs=m)

    def remove(self, ino, path, name):
        if self.posix:
            try:
                os.removexattr(path, self._osname(name))
            except OSError as e:
                raise self._map_err(e)
            return
        if self.mac:
            self._mac_call(self.mac.removexattr, os.fsencode(path),
                           self._osname(name).encode("utf-8"), 0)
            return
        m = self._sidecar_map(ino, path)
        if name not in m:
            raise NfsErr(NFS4ERR_NOXATTR)
        m.pop(name)
        self.side.update(ino, path, xattrs=m)

    def list(self, ino, path):
        """Every xattr name of the file, namespace prefix stripped."""
        if self.posix or self.mac:
            if self.posix:
                try:
                    names = os.listxattr(path)
                except OSError as e:
                    raise self._map_err(e)
            else:
                names = self._mac_list(path)
            return sorted(n[len(XATTR_NS):] for n in names
                          if n.startswith(XATTR_NS))
        return sorted(self._sidecar_map(ino, path))

    @staticmethod
    def _map_err(e):
        # "no such attribute" is ENODATA on Linux and ENOATTR (93) on
        # Darwin, where errno has no ENOATTR name to look it up by
        no_attr = (getattr(errno, "ENODATA", None),
                   getattr(errno, "ENOATTR", None),
                   93 if sys.platform == "darwin" else None)
        if e.errno in no_attr:
            return NfsErr(NFS4ERR_NOXATTR)
        if e.errno == errno.EEXIST:
            return NfsErr(NFS4ERR_EXIST)
        if e.errno in (errno.E2BIG, errno.ERANGE):
            return NfsErr(NFS4ERR_XATTR2BIG)
        if e.errno == getattr(errno, "EOPNOTSUPP", errno.EINVAL):
            return NfsErr(NFS4ERR_NOTSUPP)
        return NfsErr(oserror_to_stat(e))


# ---------------------------------------------------------------------------
# the server
# ---------------------------------------------------------------------------

class Ctx(object):
    __slots__ = ("cfh", "sfh", "uid", "gid", "gids", "minor", "clientid",
                 "session", "cur_sid", "saved_sid", "transport")

    def __init__(self, uid, gid, gids):
        self.cfh = None
        self.sfh = None
        self.uid = uid
        self.gid = gid
        self.gids = gids
        self.minor = 0        # COMPOUND minorversion (0 or 1)
        self.clientid = None  # NFSv4.1: clientid of the SEQUENCE's session
        self.session = None   # NFSv4.1: _Session of this compound
        self.cur_sid = None   # NFSv4.1 current stateid (16.2.3.1.2)
        self.saved_sid = None # NFSv4.1 saved stateid (SAVEFH/RESTOREFH)
        self.transport = "tcp"  # "tcp" or "udp" (NFSv3 only)

    def deref_sid(self, sid):
        """Substitute the current stateid for the (1, 0) special value
        (RFC 5661 sec 16.2.3.1.2); (1, 0) with no current stateid set is
        NFS4ERR_BAD_STATEID."""
        if self.minor and sid == CURRENT_SID:
            if self.cur_sid is None:
                raise NfsErr(NFS4ERR_BAD_STATEID)
            return self.cur_sid
        return sid

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
                 anon_uid=65534, anon_gid=65534, versions=(3, 4)):
        global ATTR_ENCODERS
        if ATTR_ENCODERS is None:
            ATTR_ENCODERS = _build_attr_encoders()
        self.root = root
        self.port = port
        # major NFS versions served: 3 (NFSv3 + MOUNT), 4 (NFSv4.0 + 4.1)
        self.versions = frozenset(versions)
        self.read_only = read_only
        self.lease = lease
        self.anon_uid = anon_uid
        self.anon_gid = anon_gid
        self.imap = InodeMap(root)
        self.cache = FileCache()
        self.state = State(lease)
        self.side = SideMeta(anon_uid, anon_gid)
        self.udp_enabled = False     # set once a v3 UDP listener is bound
        self.xattrs = XattrStore(self.side)
        self.xattr_ok = self.xattrs.supported(root)
        self.write_verf = os.urandom(8)
        self.symlink_ok = self._probe_symlink()
        self.excl_verfs = {}
        self.ops = self._build_ops()
        self.ops41 = self._build_ops41()
        self.ops42 = self._build_ops42()
        self.ops3 = self._build_ops3()
        self.mountops3 = self._build_mountops3()
        self.pmapops = self._build_pmapops()
        # ops a 4.1 client may send outside a session, as the only op of the
        # compound (RFC 5661 sec 2.10.2 / 18.34-18.37, 18.50)
        self.no_session_ops = frozenset([
            OP_EXCHANGE_ID, OP_CREATE_SESSION, OP_BIND_CONN_TO_SESSION,
            OP_DESTROY_SESSION, OP_DESTROY_CLIENTID])
        # per-boot server identity for EXCHANGE_ID (server_owner/scope);
        # random per boot: after a restart clients must not treat us as
        # holding their old state (handles go stale by design)
        self.owner_major = b"nfsd.py-" + os.urandom(8)
        self.supported_attrs = sorted(ATTR_ENCODERS) + [
            FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]
        # attributes newer than 4.0 are added back per minor version below
        self.supported_attrs.remove(FATTR4_SUPPATTR_EXCLCREAT)
        self.supported_attrs.remove(FATTR4_XATTR_SUPPORT)
        self.supported_attrs41 = sorted(
            self.supported_attrs + [FATTR4_SUPPATTR_EXCLCREAT])
        # NFSv4.2 adds no REQUIRED attribute we do not already have: every
        # 4.2 attribute (clone_blksize, space_freed, change_attr_type,
        # sec_label, ...) is OPTIONAL (RFC 7862 sec 12) and unsupported.
        # xattr_support (RFC 8276 sec 8.2.1) is the one 4.2-era attribute
        # we do implement, and only when the export can store xattrs.
        self.supported_attrs42 = sorted(
            self.supported_attrs41
            + ([FATTR4_XATTR_SUPPORT] if self.xattr_ok else []))
        # attrs a client may set in an EXCLUSIVE4_1 create (cva_attrs);
        # time_access_set/time_modify_set are excluded (RFC 5661 sec 18.16.3)
        self.exclcreat_attrs = [
            FATTR4_SIZE, FATTR4_MODE, FATTR4_OWNER, FATTR4_OWNER_GROUP]

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
    def supported_for(self, minor):
        """The supported_attrs bitmap of a given minor version."""
        if minor >= 2:
            return self.supported_attrs42
        if minor == 1:
            return self.supported_attrs41
        return self.supported_attrs

    def encode_fattr(self, ino, path, st, want, minor=0):
        """Return fattr4 bytes (bitmap + attrlist) for requested attrs."""
        offered = frozenset(self.supported_for(minor))
        avail = [a for a in want if a in ATTR_ENCODERS and a in offered]
        vals = Packer()
        src = _AttrSrc(self, ino, path, st, minor)
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
    def handle_rpc(self, record, transport="tcp"):
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

        if prog == PMAP_PROG:
            # Portmapper v2 (RFC 1833 sec 3), answered on every listener
            # including the -pmap port-111 sockets. Needed by v3 clients
            # whose mount_nfs has no mountport= option (OpenBSD, NetBSD,
            # DragonFly): their only way to find the MOUNT and NFS ports
            # is a GETPORT query against port 111.
            if vers != PMAP_VERS:
                pk = Packer()
                pk.uint32(PMAP_VERS)
                pk.uint32(PMAP_VERS)
                return accepted(PROG_MISMATCH, pk.get())
            fn = self.pmapops.get(proc)
            if fn is None:
                return accepted(PROC_UNAVAIL)
            try:
                return accepted(SUCCESS, fn(up))
            except XdrError as e:
                log.warning("pmap garbage args: %s", e)
                return accepted(GARBAGE_ARGS)

        if prog == MOUNT_PROGRAM:
            # MOUNT v3 (RFC 1813 sec 5) served on the same TCP port, so no
            # rpcbind is needed: mount with port=/mountport= pointing here
            if 3 not in self.versions:
                return accepted(PROG_UNAVAIL)
            if vers != MOUNT_V3:
                pk = Packer()
                pk.uint32(MOUNT_V3)
                pk.uint32(MOUNT_V3)
                return accepted(PROG_MISMATCH, pk.get())
            fn = self.mountops3.get(proc)
            if fn is None:
                return accepted(PROC_UNAVAIL)
            try:
                return accepted(SUCCESS, fn(Ctx(uid, gid, gids), up))
            except XdrError as e:
                log.warning("mount3 garbage args: %s", e)
                return accepted(GARBAGE_ARGS)

        if prog != NFS4_PROGRAM:          # == NFS_PROGRAM (100003)
            return accepted(PROG_UNAVAIL)
        if vers == NFS_V3 and 3 in self.versions:
            if proc == NFSPROC3_NULL:
                return accepted(SUCCESS)
            fn = self.ops3.get(proc)
            if fn is None:
                return accepted(PROC_UNAVAIL)
            ctx3 = Ctx(uid, gid, gids)
            ctx3.transport = transport
            try:
                body = self.v3_call(fn, proc, ctx3, up)
            except XdrError as e:
                log.warning("nfs3 garbage args: %s", e)
                return accepted(GARBAGE_ARGS)
            return accepted(SUCCESS, body)
        if vers != NFS_V4 or 4 not in self.versions or transport == "udp":
            # mismatch_info reflects only the versions being served;
            # NFSv4 is TCP-only (RFC 7530 sec 3.1 requires a transport
            # with congestion control), so over UDP only v3 is offered
            pk = Packer()
            pk.uint32(NFS_V3 if 3 in self.versions else NFS_V4)
            pk.uint32(NFS_V3 if (3 in self.versions and transport == "udp")
                      else NFS_V4 if 4 in self.versions else NFS_V3)
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
        if minor == 0:
            opstable = self.ops
        elif minor == 1:
            opstable = self.ops41
        elif minor == 2:
            opstable = self.ops42
        else:
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
        ctx.minor = minor
        results = []
        status = NFS4_OK
        slot = None
        sess = None
        cachethis = False
        remaining = nops
        # running reply size: status + padded tag + result count
        total = 12 + ((len(tag) + 3) // 4) * 4

        def err_result(opnum, stat):
            rp = Packer()
            rp.uint32(opnum)
            rp.uint32(stat)
            return rp.get()

        def cap_reply(opnum):
            """Enforce the session reply-size limits on the last result
            (RFC 5661 sec 2.10.6.1.3 / 18.36.3). Returns the capped status
            or None if the result fits."""
            nonlocal total
            grown = total + len(results[-1])
            if grown > sess.maxresp:
                stat = NFS4ERR_REP_TOO_BIG
            elif cachethis and grown > sess.maxresp_cached:
                stat = NFS4ERR_REP_TOO_BIG_TO_CACHE
            else:
                total = grown
                return None
            results[-1] = err_result(opnum, stat)
            total += len(results[-1])
            return stat

        if minor >= 1 and nops > 0:
            # RFC 5661 sec 2.10.2 (which 4.2 inherits unchanged): the first
            # op of a session-based compound is either SEQUENCE or one of
            # the few ops usable outside a session (and then it must be the
            # only op).
            opnum = up.uint32()
            remaining = nops - 1
            if opnum == OP_SEQUENCE:
                status, slot, replay, sess, cachethis = self._begin_sequence(
                    ctx, up, results, remaining)
                if replay is not None:
                    return replay
                if status != NFS4_OK:
                    remaining = 0
                else:
                    capped = cap_reply(OP_SEQUENCE)
                    if capped is not None:
                        status = capped
                        remaining = 0
            elif opnum in self.no_session_ops:
                if nops != 1:
                    status = NFS4ERR_NOT_ONLY_OP
                    results.append(err_result(opnum, status))
                    remaining = 0
                else:
                    status = self._exec_op(ctx, up, opnum, opstable, results)
                    remaining = 0
            else:
                status = NFS4ERR_OP_NOT_IN_SESSION
                results.append(err_result(opnum, status))
                remaining = 0

        for i in range(remaining):
            opnum = up.uint32()
            if sess is not None:
                if len(up.data) > sess.maxreq:
                    # request exceeds the negotiated ca_maxrequestsize
                    status = NFS4ERR_REQ_TOO_BIG
                    results.append(err_result(opnum, status))
                    break
                if i + 2 > sess.maxops:
                    # op count exceeds the negotiated ca_maxoperations
                    status = NFS4ERR_TOO_MANY_OPS
                    results.append(err_result(opnum, status))
                    break
            status = self._exec_op(ctx, up, opnum, opstable, results)
            if sess is not None:
                capped = cap_reply(opnum)
                if capped is not None:
                    status = capped
                    break
            if status != NFS4_OK:
                break

        pk = Packer()
        pk.uint32(status)
        pk.opaque(tag)
        pk.uint32(len(results))
        for r in results:
            pk.raw(r)
        reply = pk.get()
        if slot is not None:
            self.state.slot_store(slot, reply)
        return reply

    def _exec_op(self, ctx, up, opnum, opstable, results):
        """Decode and run one op, appending its result; returns its status."""
        fn = opstable.get(opnum)
        if fn is None:
            status = NFS4ERR_OP_ILLEGAL
            rp = Packer()
            rp.uint32(OP_ILLEGAL)
            rp.uint32(status)
            results.append(rp.get())
            return status
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
        return status

    def _sequence_resok(self, sess, seqid, slotid):
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque_fixed(sess.sessionid)
        pk.uint32(seqid)
        pk.uint32(slotid)
        pk.uint32(len(sess.slots) - 1)   # sr_highest_slotid
        pk.uint32(len(sess.slots) - 1)   # sr_target_highest_slotid
        pk.uint32(0)                     # sr_status_flags
        return pk.get()

    def _begin_sequence(self, ctx, up, results, remaining):
        """Handle the leading SEQUENCE op. Returns (status, slot, replay,
        sess, cachethis): replay is a complete cached compound reply to send
        verbatim (or a rebuilt NFS4ERR_RETRY_UNCACHED_REP reply when the
        original was too big to cache); slot is where to cache this
        compound's reply."""
        sessionid = up.opaque_fixed(NFS4_SESSIONID_SIZE)
        seqid = up.uint32()
        slotid = up.uint32()
        up.uint32()      # sa_highest_slotid
        cachethis = up.boolean()
        try:
            disp = self.state.sequence(sessionid, seqid, slotid)
        except NfsErr as e:
            rp = Packer()
            rp.uint32(OP_SEQUENCE)
            rp.uint32(e.stat)
            results.append(rp.get())
            return e.stat, None, None, None, False
        if disp[0] == "replay":
            cached, sess = disp[1], disp[2]
            if cached is not None:
                return NFS4_OK, None, cached, None, False
            # reply was too large to cache: RFC 5661 sec 2.10.6.1.3 -- fail
            # the op after SEQUENCE with NFS4ERR_RETRY_UNCACHED_REP
            pk = Packer()
            pk.uint32(NFS4ERR_RETRY_UNCACHED_REP)
            pk.opaque(b"")
            seq_res = Packer()
            seq_res.uint32(OP_SEQUENCE)
            seq_res.raw(self._sequence_resok(sess, seqid, slotid))
            if remaining > 0:
                opnum2 = up.uint32()
                op_res = Packer()
                op_res.uint32(opnum2)
                op_res.uint32(NFS4ERR_RETRY_UNCACHED_REP)
                pk.uint32(2)
                pk.raw(seq_res.get())
                pk.raw(op_res.get())
            else:
                pk.uint32(1)
                pk.raw(seq_res.get())
            return NFS4_OK, None, pk.get(), None, False
        sess, slot = disp[1], disp[2]
        ctx.session = sess
        ctx.clientid = sess.clientid
        rp = Packer()
        rp.uint32(OP_SEQUENCE)
        rp.raw(self._sequence_resok(sess, seqid, slotid))
        results.append(rp.get())
        return NFS4_OK, slot, None, sess, cachethis

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

    def _build_ops41(self):
        """NFSv4.1 op table: the shared 4.0 ops, minus the ops RFC 5661
        removes (MUST NOT be used -> NFS4ERR_NOTSUPP), plus the session ops.
        Optional 4.1 features we do not implement (pNFS layouts, delegations,
        backchannel, SSV) also answer NFS4ERR_NOTSUPP."""
        ops = dict(self.ops)
        for op in (OP_OPEN_CONFIRM, OP_SETCLIENTID, OP_SETCLIENTID_CONFIRM,
                   OP_RENEW, OP_RELEASE_LOCKOWNER,
                   OP_DELEGPURGE, OP_DELEGRETURN,
                   OP_BACKCHANNEL_CTL, OP_GET_DIR_DELEGATION,
                   OP_GETDEVICEINFO, OP_GETDEVICELIST, OP_LAYOUTCOMMIT,
                   OP_LAYOUTGET, OP_LAYOUTRETURN, OP_SET_SSV,
                   OP_WANT_DELEGATION):
            ops[op] = self.op_notsupp
        ops[OP_EXCHANGE_ID] = self.op_exchange_id
        ops[OP_CREATE_SESSION] = self.op_create_session
        ops[OP_DESTROY_SESSION] = self.op_destroy_session
        ops[OP_DESTROY_CLIENTID] = self.op_destroy_clientid
        ops[OP_BIND_CONN_TO_SESSION] = self.op_bind_conn_to_session
        ops[OP_SEQUENCE] = self.op_sequence_mid
        ops[OP_RECLAIM_COMPLETE] = self.op_reclaim_complete
        ops[OP_SECINFO_NO_NAME] = self.op_secinfo_no_name
        ops[OP_FREE_STATEID] = self.op_free_stateid
        ops[OP_TEST_STATEID] = self.op_test_stateid
        return ops

    def _build_ops42(self):
        """NFSv4.2 op table: the 4.1 ops plus the 4.2 additions.

        RFC 7862 introduces no REQUIRED operation -- every 4.2 operation is
        OPTIONAL (sec 1.2 / 15), so a server may answer any of them with
        NFS4ERR_NOTSUPP. We implement the ones the local filesystem can
        back honestly (SEEK, ALLOCATE, DEALLOCATE, intra-server COPY) and
        refuse the rest: CLONE needs reflink, READ_PLUS/WRITE_SAME/
        IO_ADVISE buy nothing here, inter-server COPY and the OFFLOAD_*
        asynchronous machinery need a backchannel we do not run, and the
        pNFS layout ops stay unsupported as in 4.1.
        """
        ops = dict(self.ops41)
        for op in (OP_CLONE, OP_READ_PLUS, OP_WRITE_SAME, OP_IO_ADVISE,
                   OP_COPY_NOTIFY, OP_OFFLOAD_CANCEL, OP_OFFLOAD_STATUS,
                   OP_LAYOUTERROR, OP_LAYOUTSTATS):
            ops[op] = self.op_notsupp
        ops[OP_SEEK] = self.op_seek
        ops[OP_ALLOCATE] = self.op_allocate
        ops[OP_DEALLOCATE] = self.op_deallocate
        ops[OP_COPY] = self.op_copy
        # RFC 8276 extended attributes: an optional extension of 4.2, only
        # offered when the export can actually store them
        if self.xattr_ok:
            ops[OP_GETXATTR] = self.op_getxattr
            ops[OP_SETXATTR] = self.op_setxattr
            ops[OP_LISTXATTRS] = self.op_listxattrs
            ops[OP_REMOVEXATTR] = self.op_removexattr
        return ops

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
        if ctx.minor >= 2 and self.xattr_ok and not statmod.S_ISLNK(st.st_mode):
            # RFC 8276 sec 8.5: the xattr access rights. Access to the
            # "user." namespace is governed by the file's own permissions
            # (sec 3), so they follow the read/write bits. A client that
            # does not see XAWRITE here will not even send SETXATTR.
            supported |= ACCESS4_XAREAD | ACCESS4_XAWRITE | ACCESS4_XALIST
            access |= ((ACCESS4_XAREAD | ACCESS4_XALIST) if r_ok else 0)
            access |= ACCESS4_XAWRITE if w_ok else 0
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
        sid = ctx.deref_sid(unpack_stateid(up))
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
            ctx.cur_sid = (st.gen, st.other)
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, st.gen, st.other)
            return pk.get()

        if ctx.minor:
            return work()
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
        ctx.cur_sid = None               # 16.2.3.1.2: new cfh -> (0, 0)
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
        pk.raw(self.encode_fattr(ino, path, st, sorted(want), ctx.minor))
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

    def _do_lock(self, ctx, ino, owner, ls, offset, length, locktype):
        self._lock_type_ok(ino)
        conflict = self.state.find_conflict(ino, owner, offset, length, locktype)
        if conflict is not None:
            return self._denied_body(conflict)
        self.state.lock_range(ino, owner, offset, length, locktype)
        ls.gen += 1
        ctx.cur_sid = (ls.gen, ls.other)
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
            open_sid = ctx.deref_sid(unpack_stateid(up))
            lock_seqid = up.uint32()
            clientid = up.uint64()
            owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
            if ctx.minor:
                # RFC 5661 sec 18.10.3: lock_owner4 clientid is ignored
                clientid = ctx.clientid
            o = self.state.get_open(open_sid[1])
            if o is None:
                self.state.resolve_stateid(open_sid)
                raise NfsErr(NFS4ERR_BAD_STATEID)
            open_owner = self.state.open_owner(*o.owner_key)
            lowner = (clientid, owner_bytes)

            def work():
                self.state.check_client(clientid)           # LOCK clientid
                if ctx.minor:
                    self.state.check_reclaim_done(clientid)
                self.state.resolve_stateid(open_sid, ino)   # open gen check
                lock_own = self.state.lock_owner(clientid, owner_bytes)
                ls = self.state.lock_state_for(lowner, ino)
                lock_own.seqid = lock_seqid          # establish lock-owner base
                body = self._do_lock(ctx, ino, lowner, ls, offset, length,
                                     locktype)
                # cache under the lock-owner too (for lock-owner replays)
                self.state.seqid_commit(lock_own, lock_seqid, body)
                return body

            if ctx.minor:
                return work()
            return self._seqid_dispatch(open_owner, open_seqid, OP_LOCK, work)
        else:
            lock_sid = ctx.deref_sid(unpack_stateid(up))
            lock_seqid = up.uint32()
            ls0 = self.state.get_lock_state(lock_sid[1])
            if ls0 is None:
                self.state.resolve_stateid(lock_sid)
                raise NfsErr(NFS4ERR_BAD_STATEID)
            lock_own = self.state.lock_owner(*ls0.owner)

            def work():
                ls = self.state.resolve_stateid(lock_sid, ino)
                return self._do_lock(ctx, ino, ls0.owner, ls, offset, length,
                                     locktype)

            if ctx.minor:
                return work()
            return self._seqid_dispatch(lock_own, lock_seqid, OP_LOCK, work)

    def op_lockt(self, ctx, up):
        locktype = up.uint32()
        offset = up.uint64()
        length = up.uint64()
        clientid = up.uint64()
        owner_bytes = up.opaque(NFS4_OPAQUE_LIMIT)
        if ctx.minor:
            clientid = ctx.clientid      # 4.1: session clientid governs
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
        lock_sid = ctx.deref_sid(unpack_stateid(up))
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
            ctx.cur_sid = (ls.gen, ls.other)
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, ls.gen, ls.other)
            return pk.get()

        if ctx.minor:
            return work()
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
        ctx.cur_sid = None               # 16.2.3.1.2: new cfh -> (0, 0)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_lookupp(self, ctx, up):
        ino = ctx.need_cfh()
        self.dir_path_of(ino)          # non-directory cfh -> NFS4ERR_NOTDIR
        if ino == ROOT_INO:
            raise NfsErr(NFS4ERR_NOENT)
        ctx.cfh = self.imap.parent_of(ino)
        ctx.cur_sid = None               # 16.2.3.1.2: new cfh -> (0, 0)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def _verify_common(self, ctx, up):
        bits = unpack_bitmap(up)
        theirs = up.opaque()
        offered = frozenset(self.supported_for(ctx.minor))
        for a in bits:
            if a in (FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET,
                     FATTR4_RDATTR_ERROR):
                raise NfsErr(NFS4ERR_INVAL)
            if a not in ATTR_ENCODERS or a not in offered:
                # unknown, or newer than this compound's minor version
                raise NfsErr(NFS4ERR_ATTRNOTSUPP)
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        vals = Packer()
        src = _AttrSrc(self, ino, path, st, ctx.minor)
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
        deleg_want = 0
        if ctx.minor:
            # RFC 5661 sec 18.16.3: the open_owner4 clientid field is
            # ignored; the session's clientid governs
            clientid = ctx.clientid
            # 4.1 share_access carries WANT_* delegation hints; we never
            # grant delegations (no backchannel), so strip them and keep
            # the plain access bits (RFC 5661 sec 18.16.3)
            deleg_want = share_access & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK
            share_access &= ~(OPEN4_SHARE_ACCESS_WANT_DELEG_MASK
                              | OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL
                              | OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED)
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
            elif createhow == EXCLUSIVE4:
                cverf = up.opaque_fixed(NFS4_VERIFIER_SIZE)
            elif createhow == EXCLUSIVE4_1 and ctx.minor:
                cverf = up.opaque_fixed(NFS4_VERIFIER_SIZE)
                bits = unpack_bitmap(up)
                alist = Unpacker(up.opaque())
                if (FATTR4_TIME_ACCESS_SET in bits
                        or FATTR4_TIME_MODIFY_SET in bits):
                    raise NfsErr(NFS4ERR_INVAL)   # 18.16.3: MUST NOT set
                cvals = self.decode_settable(bits, alist, for_create=True)
            else:
                raise XdrError("createhow4 %d" % createhow)
        claim = up.uint32()
        claim_name = None
        if claim == CLAIM_NULL:
            claim_name = up.string()
        owner = self.state.open_owner(clientid, owner_bytes)

        def open_by(ino, dpath, before, applied):
            """Shared tail of OPEN: type/access/share checks, state, resok."""
            path2 = self.path_of(ino)
            st = self.lstat(path2)
            if statmod.S_ISDIR(st.st_mode):
                raise NfsErr(NFS4ERR_ISDIR)
            if not statmod.S_ISREG(st.st_mode):
                raise NfsErr(NFS4ERR_SYMLINK)
            if opentype != OPEN4_CREATE:
                uid, gid, mode = self.file_ugm(ino, path2, st)
                if not self.check_access(ctx, st, uid, gid, mode,
                                         bool(share_access
                                              & OPEN4_SHARE_ACCESS_READ),
                                         bool(share_access
                                              & OPEN4_SHARE_ACCESS_WRITE),
                                         False):
                    raise NfsErr(NFS4ERR_ACCESS)
            if self.state.share_conflict(ino, share_access, share_deny,
                                         (clientid, owner_bytes)):
                raise NfsErr(NFS4ERR_SHARE_DENIED)

            o, is_new = self.state.open_file(clientid, owner_bytes, ino,
                                             share_access, share_deny, ctx.uid)
            if ctx.minor:
                # NFSv4.1 has no OPEN_CONFIRM: opens are born confirmed
                # (RFC 5661 sec 18.16.3) and the CONFIRM rflag MUST NOT be set
                owner.confirmed = True
                need_confirm = False
            else:
                need_confirm = not owner.confirmed
            if is_new:
                o.confirmed = owner.confirmed
            ctx.cfh = ino
            ctx.cur_sid = (o.gen, o.other)
            rflags = OPEN4_RESULT_LOCKTYPE_POSIX
            if need_confirm:
                rflags |= OPEN4_RESULT_CONFIRM
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, o.gen, o.other)
            pk.boolean(False)
            pk.uint64(before)
            pk.uint64(self.dir_cinfo(dpath) if dpath else before)
            pk.uint32(rflags)
            pk.raw(pack_bitmap(applied))
            if deleg_want != OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE:
                # the client expressed a WANT_*: answer with the extended
                # no-delegation form and the reason (RFC 5661 sec 18.16.3)
                pk.uint32(OPEN_DELEGATE_NONE_EXT)
                if deleg_want == OPEN4_SHARE_ACCESS_WANT_NO_DELEG:
                    pk.uint32(WND4_NOT_WANTED)
                elif deleg_want == OPEN4_SHARE_ACCESS_WANT_CANCEL:
                    pk.uint32(WND4_CANCELLED)
                else:
                    pk.uint32(WND4_RESOURCE)
                    pk.boolean(False)    # ond_server_will_signal_avail
            else:
                pk.uint32(OPEN_DELEGATE_NONE)
            return pk.get()

        def work():
            if claim != CLAIM_NULL and not (claim == CLAIM_FH and ctx.minor):
                if claim == CLAIM_PREVIOUS:
                    raise NfsErr(NFS4ERR_NO_GRACE)
                raise NfsErr(NFS4ERR_NOTSUPP)
            if share_access & ~OPEN4_SHARE_ACCESS_BOTH or share_access == 0:
                raise NfsErr(NFS4ERR_INVAL)
            if share_deny & ~OPEN4_SHARE_DENY_BOTH:
                raise NfsErr(NFS4ERR_INVAL)
            self.state.check_client(clientid)
            if ctx.minor:
                self.state.check_reclaim_done(clientid)
            wants_write = bool(share_access & OPEN4_SHARE_ACCESS_WRITE)
            if claim == CLAIM_FH:
                # RFC 5661 sec 18.16.3: open of an existing file by its
                # filehandle (CURRENT_FH is the file, not the directory);
                # change_info in the reply is of no consequence
                if opentype == OPEN4_CREATE:
                    raise NfsErr(NFS4ERR_INVAL)
                if self.read_only and wants_write:
                    raise NfsErr(NFS4ERR_ROFS)
                return open_by(ctx.need_cfh(), None, 0, [])
            dir_ino = ctx.need_cfh()
            dpath = self.path_of(dir_ino)
            path = self.child_path(dir_ino, claim_name)
            if self.read_only and (wants_write or opentype == OPEN4_CREATE):
                raise NfsErr(NFS4ERR_ROFS)

            before = self.dir_cinfo(dpath)
            applied = []
            if opentype == OPEN4_CREATE:
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
                existed = os.path.lexists(path)
                if createhow in (EXCLUSIVE4, EXCLUSIVE4_1):
                    ino0 = self.imap.get_child(dir_ino, claim_name)
                    if existed:
                        prev = self.excl_verfs.get(ino0) if ino0 else None
                        if prev != cverf:
                            raise NfsErr(NFS4ERR_EXIST)
                    else:
                        fd = os.open(path, flags | os.O_EXCL,
                                     cvals.get("mode", 0o644))
                        os.close(fd)
                        ino0 = self.imap.get_or_alloc(dir_ino, claim_name)
                        self.excl_verfs[ino0] = cverf
                        if cvals:              # EXCLUSIVE4_1 cva_attrs
                            try:
                                applied += self.apply_attrs(ino0, path, cvals)
                            except OSError:
                                pass
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
            return open_by(ino, dpath, before, applied)

        if ctx.minor:
            # 4.1: the owner seqid field is ignored; sessions provide the
            # exactly-once semantics (RFC 5661 sec 8.13)
            return work()
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
        sid = ctx.deref_sid(unpack_stateid(up))
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
            ctx.cur_sid = (st.gen, st.other)
            pk = Packer()
            pk.uint32(NFS4_OK)
            pack_stateid(pk, st.gen, st.other)
            return pk.get()

        if ctx.minor:
            return work()
        return self._seqid_dispatch(owner, seqid, OP_OPEN_DOWNGRADE, work)

    def op_putfh(self, ctx, up):
        fh = up.opaque(NFS4_FHSIZE)
        ctx.cfh = fh_ino(fh)
        ctx.cur_sid = None               # 16.2.3.1.2: new cfh -> (0, 0)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_putrootfh(self, ctx, up):
        ctx.cfh = ROOT_INO
        ctx.cur_sid = None               # 16.2.3.1.2: new cfh -> (0, 0)
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
        sid = ctx.deref_sid(unpack_stateid(up))
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
            ep.raw(self.encode_fattr(cino, cpath, st, want, ctx.minor))
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
        ctx.cur_sid = ctx.saved_sid      # fh + stateid restored as a set
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_savefh(self, ctx, up):
        ctx.sfh = ctx.need_cfh()
        ctx.saved_sid = ctx.cur_sid      # fh + stateid saved as a set
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
        if ctx.minor:
            ctx.cfh = None   # 4.1: consumed on success (RFC 5661 sec 18.29.3)
            ctx.cur_sid = None
        return pk.get()

    def op_setattr(self, ctx, up):
        sid = ctx.deref_sid(unpack_stateid(up))
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

    # -- NFSv4.1 session ops (RFC 5661 / RFC 5662 XDR) ---------------------
    def op_notsupp(self, ctx, up):
        raise NfsErr(NFS4ERR_NOTSUPP)

    def op_sequence_mid(self, ctx, up):
        # a SEQUENCE that is not the first op (RFC 5661 sec 18.46.3)
        raise NfsErr(NFS4ERR_SEQUENCE_POS)

    # eia_flags a client may set (RFC 5661 sec 18.35.3); any other bit,
    # including reply-only EXCHGID4_FLAG_CONFIRMED_R, is NFS4ERR_INVAL
    EIA_FLAGS_OK = (EXCHGID4_FLAG_SUPP_MOVED_REFER
                    | EXCHGID4_FLAG_SUPP_MOVED_MIGR
                    | EXCHGID4_FLAG_BIND_PRINC_STATEID
                    | EXCHGID4_FLAG_USE_NON_PNFS
                    | EXCHGID4_FLAG_USE_PNFS_MDS
                    | EXCHGID4_FLAG_USE_PNFS_DS
                    | EXCHGID4_FLAG_UPD_CONFIRMED_REC_A)

    def op_exchange_id(self, ctx, up):
        verifier = up.opaque_fixed(NFS4_VERIFIER_SIZE)
        owner_id = up.opaque(NFS4_OPAQUE_LIMIT)
        flags = up.uint32()
        spa_how = up.uint32()
        if spa_how != SP4_NONE:
            # no RPCSEC_GSS -> no machine-cred / SSV state protection
            raise NfsErr(NFS4ERR_NOTSUPP)
        n_impl = up.uint32()
        if n_impl > 1:
            raise XdrError("eia_client_impl_id<1>")
        if n_impl == 1:
            up.string()      # nii_domain
            up.string()      # nii_name
            up.int64()       # nii_date.seconds
            up.uint32()      # nii_date.nseconds
        if flags & ~self.EIA_FLAGS_OK:
            raise NfsErr(NFS4ERR_INVAL)  # undefined/reply-only bits (18.35.3)
        clientid, eir_seq, confirmed = self.state.exchange_id(
            verifier, owner_id, ctx.uid,
            update=bool(flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A))
        out_flags = EXCHGID4_FLAG_USE_NON_PNFS
        if confirmed:
            out_flags |= EXCHGID4_FLAG_CONFIRMED_R
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint64(clientid)
        pk.uint32(eir_seq)
        pk.uint32(out_flags)
        pk.uint32(SP4_NONE)              # eir_state_protect
        pk.uint64(0)                     # so_minor_id
        pk.opaque(self.owner_major)      # so_major_id
        pk.opaque(self.owner_major)      # eir_server_scope
        pk.uint32(0)                     # eir_server_impl_id: none
        return pk.get()

    @staticmethod
    def _chan_attrs(up):
        """Decode channel_attrs4 -> (headerpad, maxreq, maxresp,
        maxresp_cached, maxops, maxreqs)."""
        vals = (up.uint32(), up.uint32(), up.uint32(),
                up.uint32(), up.uint32(), up.uint32())
        n_ird = up.uint32()              # ca_rdma_ird<1>
        if n_ird > 1:
            raise XdrError("ca_rdma_ird<1>")
        for _ in range(n_ird):
            up.uint32()
        return vals

    @staticmethod
    def _pack_chan_attrs(pk, attrs, nslots, cache_limit):
        """Pack the negotiated channel_attrs4: each value may only be
        adjusted downward from the client's ask (RFC 5661 sec 18.36.3)."""
        pk.uint32(0)                                   # ca_headerpadsize
        pk.uint32(min(attrs[1], MAX_RPC_RECORD))       # ca_maxrequestsize
        pk.uint32(min(attrs[2], MAX_RPC_RECORD))       # ca_maxresponsesize
        pk.uint32(min(attrs[3], cache_limit))          # ..._cached
        pk.uint32(min(attrs[4], 256))                  # ca_maxoperations
        pk.uint32(nslots)                              # ca_maxrequests
        pk.uint32(0)                                   # ca_rdma_ird: none
        return pk

    def _skip_sec_parms(self, up):
        """Consume one callback_sec_parms4 (we run no backchannel)."""
        flavor = up.uint32()
        if flavor == AUTH_SYS:
            up.uint32()                  # stamp
            up.string()                  # machinename
            up.uint32()                  # uid
            up.uint32()                  # gid
            n = up.uint32()              # gids<16>
            if n > 16:
                raise XdrError("authsys gids")
            for _ in range(n):
                up.uint32()
        elif flavor == RPCSEC_GSS:
            up.uint32()                  # gcbp_service
            up.opaque()                  # gcbp_handle_from_server
            up.opaque()                  # gcbp_handle_from_client
        elif flavor != AUTH_NONE:
            raise XdrError("callback_sec_parms4 flavor")

    # csa_flags a client may set (RFC 5661 sec 18.36.3)
    CSA_FLAGS_OK = (CREATE_SESSION4_FLAG_PERSIST
                    | CREATE_SESSION4_FLAG_CONN_BACK_CHAN
                    | CREATE_SESSION4_FLAG_CONN_RDMA)
    # below this, a channel could not carry even a minimal COMPOUND
    CHAN_SIZE_FLOOR = 128

    def op_create_session(self, ctx, up):
        clientid = up.uint64()
        seq = up.uint32()
        csa_flags = up.uint32()
        fore = self._chan_attrs(up)
        back = self._chan_attrs(up)
        up.uint32()                      # csa_cb_program
        n_sec = up.uint32()
        if n_sec > 16:
            raise XdrError("csa_sec_parms")
        for _ in range(n_sec):
            self._skip_sec_parms(up)
        if csa_flags & ~self.CSA_FLAGS_OK:
            raise NfsErr(NFS4ERR_INVAL)  # undefined flag bits (18.36.3)
        for ch in (fore, back):
            # ca_maxrequestsize/ca_maxresponsesize too small to ever carry
            # a request/reply -> NFS4ERR_TOOSMALL (RFC 5661 sec 18.36.3)
            if ch[1] < self.CHAN_SIZE_FLOOR or ch[2] < self.CHAN_SIZE_FLOOR:
                raise NfsErr(NFS4ERR_TOOSMALL)
        nslots = max(1, min(fore[5], MAX_SESSION_SLOTS))

        def make_session(cid):
            sess = _Session(self.state._new_sessionid(), cid, nslots,
                            min(fore[1], MAX_RPC_RECORD),
                            min(fore[2], MAX_RPC_RECORD),
                            min(fore[3], SLOT_CACHE_LIMIT),
                            min(fore[4], 256))
            pk = Packer()
            pk.uint32(NFS4_OK)
            pk.opaque_fixed(sess.sessionid)
            pk.uint32(seq)
            pk.uint32(0)                 # csr_flags: no CONN_BACK_CHAN
            pk.uint32(0)                 # fore ca_headerpadsize
            pk.uint32(sess.maxreq)
            pk.uint32(sess.maxresp)
            pk.uint32(sess.maxresp_cached)
            pk.uint32(sess.maxops)
            pk.uint32(len(sess.slots))
            pk.uint32(0)                 # fore ca_rdma_ird: none
            self._pack_chan_attrs(pk, back, back[5], back[3])
            return sess, pk.get()

        return self.state.create_session(clientid, seq, ctx.uid, make_session)

    def op_destroy_session(self, ctx, up):
        sessionid = up.opaque_fixed(NFS4_SESSIONID_SIZE)
        self.state.destroy_session(sessionid)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_destroy_clientid(self, ctx, up):
        clientid = up.uint64()
        self.state.destroy_clientid(clientid)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_bind_conn_to_session(self, ctx, up):
        sessionid = up.opaque_fixed(NFS4_SESSIONID_SIZE)
        up.uint32()                      # bctsa_dir
        up.boolean()                     # bctsa_use_conn_in_rdma_mode
        sess = self.state.find_session(sessionid)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque_fixed(sess.sessionid)
        pk.uint32(CDFS4_FORE)            # fore channel only (no callbacks)
        pk.boolean(False)
        return pk.get()

    def op_reclaim_complete(self, ctx, up):
        one_fs = up.boolean()
        if ctx.session is None:
            raise NfsErr(NFS4ERR_OP_NOT_IN_SESSION)
        self.state.reclaim_complete(ctx.clientid, one_fs)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_secinfo_no_name(self, ctx, up):
        style = up.uint32()
        if style not in (SECINFO_STYLE4_CURRENT_FH, SECINFO_STYLE4_PARENT):
            raise NfsErr(NFS4ERR_INVAL)
        ino = ctx.need_cfh()
        if style == SECINFO_STYLE4_PARENT:
            self.dir_path_of(ino)        # must be a directory
            if ino == ROOT_INO:
                raise NfsErr(NFS4ERR_NOENT)   # the root has no parent
        else:
            self.path_of(ino)            # object must still resolve
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint32(2)
        pk.uint32(AUTH_SYS)
        pk.uint32(AUTH_NONE)
        ctx.cfh = None                   # consumed on success (18.45.3)
        ctx.cur_sid = None
        return pk.get()

    def op_free_stateid(self, ctx, up):
        sid = ctx.deref_sid(unpack_stateid(up))
        self.state.free_stateid(sid)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_test_stateid(self, ctx, up):
        n = up.uint32()
        if n > 1024:
            raise NfsErr(NFS4ERR_RESOURCE)
        sids = [unpack_stateid(up) for _ in range(n)]
        codes = []
        for sid in sids:
            if sid == ZERO_STATEID or sid == ONES_STATEID:
                codes.append(NFS4ERR_BAD_STATEID)
                continue
            try:
                self.state.resolve_stateid(sid)
                codes.append(NFS4_OK)
            except NfsErr as e:
                codes.append(e.stat)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint32(len(codes))
        for c in codes:
            pk.uint32(c)
        return pk.get()

    # -- NFSv4.2 ops (RFC 7862 sec 15 / RFC 7863 XDR) ----------------------
    # All of NFSv4.2 is OPTIONAL, so each of these may also legitimately
    # answer NFS4ERR_NOTSUPP; we implement what the local filesystem backs.

    def _v42_write_target(self, ctx, sid):
        """CURRENT_FH of a 4.2 space op: a regular file the stateid may
        write (RFC 7862 sec 15.1.3/15.4.3: WRONG_TYPE if not regular)."""
        ino = ctx.need_cfh()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        path = self.path_of(ino)
        st = self.lstat(path)
        if statmod.S_ISDIR(st.st_mode):
            raise NfsErr(NFS4ERR_WRONG_TYPE)
        if not statmod.S_ISREG(st.st_mode):
            raise NfsErr(NFS4ERR_WRONG_TYPE)
        self._check_stateid_for_io(sid, ino, need_write=True)
        return ino, path

    @staticmethod
    def _v42_range(offset, length):
        if length == 0:
            raise NfsErr(NFS4ERR_INVAL)
        if offset + length > NFS4_INT64_MAX:
            raise NfsErr(NFS4ERR_INVAL)
        return offset, length

    def op_seek(self, ctx, up):
        sid = ctx.deref_sid(unpack_stateid(up))
        offset = up.uint64()
        what = up.uint32()
        if what not in (NFS4_CONTENT_DATA, NFS4_CONTENT_HOLE):
            raise NfsErr(NFS4ERR_UNION_NOTSUPP)
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        self._require_regular(path)
        self._check_stateid_for_io(sid, ino)
        e = self.cache.get(ino, path, False)
        size = FileCache.size(e)
        if offset >= size:
            # RFC 7862 sec 15.11.3: past EOF is NFS4ERR_NXIO
            raise NfsErr(NFS4ERR_NXIO)
        whence = (getattr(os, "SEEK_DATA", None) if what == NFS4_CONTENT_DATA
                  else getattr(os, "SEEK_HOLE", None))
        if whence is None:
            # No sparse-seek support (Windows, older kernels): report the
            # file as one extent -- data starts here, and every file has a
            # virtual hole at EOF (RFC 7862 sec 15.11.3).
            found = offset if what == NFS4_CONTENT_DATA else size
            eof = False
        else:
            try:
                found = FileCache.lseek(e, offset, whence)
                eof = False
            except OSError as err:
                if err.errno != errno.ENXIO:
                    raise NfsErr(oserror_to_stat(err))
                # ENXIO from SEEK_DATA: no data after offset -> sr_eof
                found = size
                eof = True
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.boolean(eof)
        pk.uint64(found)
        return pk.get()

    def op_allocate(self, ctx, up):
        sid = ctx.deref_sid(unpack_stateid(up))
        offset = up.uint64()
        length = up.uint64()
        self._v42_range(offset, length)
        ino, path = self._v42_write_target(ctx, sid)
        e = self.cache.get(ino, path, True)
        try:
            FileCache.fallocate(e, offset, length)
        except OSError as err:
            raise NfsErr(oserror_to_stat(err))
        except NotImplementedError:
            raise NfsErr(NFS4ERR_NOTSUPP)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_deallocate(self, ctx, up):
        sid = ctx.deref_sid(unpack_stateid(up))
        offset = up.uint64()
        length = up.uint64()
        self._v42_range(offset, length)
        ino, path = self._v42_write_target(ctx, sid)
        e = self.cache.get(ino, path, True)
        try:
            FileCache.punch_hole(e, offset, length)
        except OSError as err:
            raise NfsErr(oserror_to_stat(err))
        except NotImplementedError:
            raise NfsErr(NFS4ERR_NOTSUPP)
        pk = Packer()
        pk.uint32(NFS4_OK)
        return pk.get()

    def op_copy(self, ctx, up):
        src_sid = ctx.deref_sid(unpack_stateid(up))
        dst_sid = ctx.deref_sid(unpack_stateid(up))
        src_offset = up.uint64()
        dst_offset = up.uint64()
        count = up.uint64()
        up.boolean()                     # ca_consecutive
        synchronous = up.boolean()
        n_src = up.uint32()
        if n_src:
            # inter-server copy: we are never a copy destination for a
            # remote source (RFC 7862 sec 15.2.3)
            raise NfsErr(NFS4ERR_NOTSUPP)
        src_ino = ctx.need_sfh()
        dst_ino = ctx.need_cfh()
        if self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        src_path = self.path_of(src_ino)
        dst_path = self.path_of(dst_ino)
        self._require_regular(src_path)
        self._require_regular(dst_path)
        if src_ino == dst_ino:
            # overlapping intra-file copy is the CLONE use case; refuse
            raise NfsErr(NFS4ERR_INVAL)
        self._check_stateid_for_io(src_sid, src_ino)
        self._check_stateid_for_io(dst_sid, dst_ino, need_write=True)
        se = self.cache.get(src_ino, src_path, False)
        de = self.cache.get(dst_ino, dst_path, True)
        src_size = FileCache.size(se)
        if src_offset > src_size:
            raise NfsErr(NFS4ERR_INVAL)
        todo = (src_size - src_offset) if count == 0 else count
        if src_offset + todo > src_size:
            raise NfsErr(NFS4ERR_INVAL)
        copied = 0
        while copied < todo:
            chunk = FileCache.pread(se, min(MAXIO, todo - copied),
                                    src_offset + copied)
            if not chunk:
                break
            wrote = FileCache.pwrite(de, chunk, dst_offset + copied)
            copied += wrote
        FileCache.fsync(de)
        pk = Packer()
        pk.uint32(NFS4_OK)
        # write_response4: no callback stateid (we copied synchronously)
        pk.uint32(0)                     # wr_callback_id<1>: empty
        pk.uint64(copied)
        pk.uint32(FILE_SYNC4)
        pk.opaque_fixed(self.write_verf)
        # copy_requirements4: we always copy consecutively and synchronously
        pk.boolean(True)                 # cr_consecutive
        pk.boolean(True)                 # cr_synchronous
        return pk.get()

    # -- extended attributes (RFC 8276 sec 8.4), an NFSv4.2 extension ------

    def _xattr_target(self, ctx, writing):
        """CURRENT_FH of an xattr op, plus its pre-op change id."""
        ino = ctx.need_cfh()
        path = self.path_of(ino)
        st = self.lstat(path)
        if statmod.S_ISLNK(st.st_mode):
            # xattrs are looked up on the symlink itself, which no POSIX
            # user namespace allows
            raise NfsErr(NFS4ERR_WRONG_TYPE)
        if writing and self.read_only:
            raise NfsErr(NFS4ERR_ROFS)
        return ino, path, self.change_of(st)

    def _xattr_change_info(self, pk, path, before):
        pk.boolean(False)                # not atomic with the operation
        pk.uint64(before)
        pk.uint64(self.dir_cinfo(path))

    @staticmethod
    def _xattr_name(up):
        name = up.string(NFS4_OPAQUE_LIMIT)
        if not name:
            raise NfsErr(NFS4ERR_INVAL)
        return name

    def op_getxattr(self, ctx, up):
        name = self._xattr_name(up)
        ino, path, _ = self._xattr_target(ctx, False)
        value = self.xattrs.get(ino, path, name)
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.opaque(value)
        return pk.get()

    def op_setxattr(self, ctx, up):
        option = up.uint32()
        if option not in (SETXATTR4_EITHER, SETXATTR4_CREATE,
                          SETXATTR4_REPLACE):
            raise NfsErr(NFS4ERR_INVAL)
        name = self._xattr_name(up)
        value = up.opaque()
        ino, path, before = self._xattr_target(ctx, True)
        self.xattrs.set(ino, path, name, value, option)
        pk = Packer()
        pk.uint32(NFS4_OK)
        self._xattr_change_info(pk, path, before)
        return pk.get()

    def op_removexattr(self, ctx, up):
        name = self._xattr_name(up)
        ino, path, before = self._xattr_target(ctx, True)
        self.xattrs.remove(ino, path, name)
        pk = Packer()
        pk.uint32(NFS4_OK)
        self._xattr_change_info(pk, path, before)
        return pk.get()

    def op_listxattrs(self, ctx, up):
        cookie = up.uint64()
        maxcount = up.uint32()
        ino, path, _ = self._xattr_target(ctx, False)
        names = self.xattrs.list(ino, path)
        if cookie > len(names):
            raise NfsErr(NFS4ERR_BAD_COOKIE)
        body = Packer()
        # cookie(8) + name count(4) + eof(4)
        used = 16
        emitted = 0
        eof = True
        for i in range(int(cookie), len(names)):
            nb = Packer()
            nb.string(names[i])
            b = nb.get()
            if used + len(b) > maxcount:
                if not emitted:
                    raise NfsErr(NFS4ERR_TOOSMALL)
                eof = False
                break
            body.raw(b)
            used += len(b)
            emitted += 1
        pk = Packer()
        pk.uint32(NFS4_OK)
        pk.uint64(int(cookie) + emitted)  # lxr_cookie: resume point
        pk.uint32(emitted)
        pk.raw(body.get())
        pk.boolean(eof)
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
        sid = ctx.deref_sid(unpack_stateid(up))
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

    # =======================================================================
    # NFSv3 (RFC 1813) + MOUNT v3 -- stateless, shares the VFS layer.
    # Wire layouts follow the RFC 1813 XDR (spec/rfc1813.txt).
    # =======================================================================

    def _build_ops3(self):
        return {
            NFSPROC3_GETATTR: self.v3_getattr,
            NFSPROC3_SETATTR: self.v3_setattr,
            NFSPROC3_LOOKUP: self.v3_lookup,
            NFSPROC3_ACCESS: self.v3_access,
            NFSPROC3_READLINK: self.v3_readlink,
            NFSPROC3_READ: self.v3_read,
            NFSPROC3_WRITE: self.v3_write,
            NFSPROC3_CREATE: self.v3_create,
            NFSPROC3_MKDIR: self.v3_mkdir,
            NFSPROC3_SYMLINK: self.v3_symlink,
            NFSPROC3_MKNOD: self.v3_mknod,
            NFSPROC3_REMOVE: self.v3_remove,
            NFSPROC3_RMDIR: self.v3_rmdir,
            NFSPROC3_RENAME: self.v3_rename,
            NFSPROC3_LINK: self.v3_link,
            NFSPROC3_READDIR: self.v3_readdir,
            NFSPROC3_READDIRPLUS: self.v3_readdirplus,
            NFSPROC3_FSSTAT: self.v3_fsstat,
            NFSPROC3_FSINFO: self.v3_fsinfo,
            NFSPROC3_PATHCONF: self.v3_pathconf,
            NFSPROC3_COMMIT: self.v3_commit,
        }

    def _build_mountops3(self):
        return {
            MOUNTPROC3_NULL: self.mnt3_null,
            MOUNTPROC3_MNT: self.mnt3_mnt,
            MOUNTPROC3_DUMP: self.mnt3_dump,
            MOUNTPROC3_UMNT: self.mnt3_umnt,
            MOUNTPROC3_UMNTALL: self.mnt3_null,
            MOUNTPROC3_EXPORT: self.mnt3_export,
        }

    # -- portmapper v2 (RFC 1833 sec 3): a static table pointing every
    # program we serve at our own port. PMAPPROC_CALLIT is intentionally
    # absent (broadcast indirect call; unavailable is the safe answer).
    def _build_pmapops(self):
        return {
            PMAPPROC_NULL: self.pmap_null,
            PMAPPROC_SET: self.pmap_set,
            PMAPPROC_UNSET: self.pmap_set,
            PMAPPROC_GETPORT: self.pmap_getport,
            PMAPPROC_DUMP: self.pmap_dump,
        }

    def _pmap_mappings(self):
        """Every (prog, vers, prot, port) tuple this server serves. All
        programs share the one listener port, tcp and (for v3) udp."""
        out = []
        if 3 in self.versions:
            out.append((NFS_PROGRAM, NFS_V3, IPPROTO_TCP, self.port))
        if 4 in self.versions:
            out.append((NFS_PROGRAM, NFS_V4, IPPROTO_TCP, self.port))
        if 3 in self.versions:
            out.append((MOUNT_PROGRAM, MOUNT_V3, IPPROTO_TCP, self.port))
        if 3 in self.versions and self.udp_enabled:
            out.append((NFS_PROGRAM, NFS_V3, IPPROTO_UDP, self.port))
            out.append((MOUNT_PROGRAM, MOUNT_V3, IPPROTO_UDP, self.port))
        return tuple(out)

    def pmap_null(self, up):
        return b""

    def pmap_set(self, up):
        # Static table: SET/UNSET always refused ("FALSE" reply, RFC 1833
        # sec 3.2 -- the mapping cannot be established/removed).
        pk = Packer()
        pk.uint32(0)
        return pk.get()

    def pmap_getport(self, up):
        prog = up.uint32()
        vers = up.uint32()
        prot = up.uint32()
        up.uint32()          # port: ignored per RFC 1833 sec 3.2
        port = 0             # "A port value of zeros means the program
                             #  has not been registered."
        for m_prog, m_vers, m_prot, m_port in self._pmap_mappings():
            if prog == m_prog and prot == m_prot:
                port = m_port
                if vers == m_vers:
                    break
        pk = Packer()
        pk.uint32(port)
        return pk.get()

    def pmap_dump(self, up):
        pk = Packer()
        for m_prog, m_vers, m_prot, m_port in self._pmap_mappings():
            pk.uint32(1)     # pmaplist: a mapping follows
            pk.uint32(m_prog)
            pk.uint32(m_vers)
            pk.uint32(m_prot)
            pk.uint32(m_port)
        pk.uint32(0)         # end of list
        return pk.get()

    # nfsstat3 values (RFC 1813 sec 2.6); shared codes are numerically
    # identical to their NFSv4 counterparts, so most NfsErr values pass
    # through unchanged
    V3_STATS = frozenset([
        NFS3ERR_PERM, NFS3ERR_NOENT, NFS3ERR_IO, NFS3ERR_NXIO,
        NFS3ERR_ACCES, NFS3ERR_EXIST, NFS3ERR_XDEV, NFS3ERR_NODEV,
        NFS3ERR_NOTDIR, NFS3ERR_ISDIR, NFS3ERR_INVAL, NFS3ERR_FBIG,
        NFS3ERR_NOSPC, NFS3ERR_ROFS, NFS3ERR_MLINK, NFS3ERR_NAMETOOLONG,
        NFS3ERR_NOTEMPTY, NFS3ERR_DQUOT, NFS3ERR_STALE, NFS3ERR_REMOTE,
        NFS3ERR_BADHANDLE, NFS3ERR_NOT_SYNC, NFS3ERR_BAD_COOKIE,
        NFS3ERR_NOTSUPP, NFS3ERR_TOOSMALL, NFS3ERR_SERVERFAULT,
        NFS3ERR_BADTYPE, NFS3ERR_JUKEBOX,
    ])

    # count of trailing "attributes_follow = FALSE" booleans in each
    # procedure's resfail arm (post_op_attr = 1, wcc_data = 2)
    V3_FAIL_SHAPE = {
        NFSPROC3_GETATTR: 0, NFSPROC3_SETATTR: 2, NFSPROC3_LOOKUP: 1,
        NFSPROC3_ACCESS: 1, NFSPROC3_READLINK: 1, NFSPROC3_READ: 1,
        NFSPROC3_WRITE: 2, NFSPROC3_CREATE: 2, NFSPROC3_MKDIR: 2,
        NFSPROC3_SYMLINK: 2, NFSPROC3_MKNOD: 2, NFSPROC3_REMOVE: 2,
        NFSPROC3_RMDIR: 2, NFSPROC3_RENAME: 4, NFSPROC3_LINK: 3,
        NFSPROC3_READDIR: 1, NFSPROC3_READDIRPLUS: 1, NFSPROC3_FSSTAT: 1,
        NFSPROC3_FSINFO: 1, NFSPROC3_PATHCONF: 1, NFSPROC3_COMMIT: 2,
    }

    def v3_call(self, fn, proc, ctx, up):
        """Run one NFSv3 procedure, mapping errors to a resfail body."""
        try:
            return fn(ctx, up)
        except NfsErr as e:
            stat = e.stat if e.stat in self.V3_STATS else NFS3ERR_SERVERFAULT
        except OverflowError:
            stat = NFS3ERR_INVAL
        except OSError as e:
            stat = oserror_to_stat(e)
            if stat not in self.V3_STATS:
                stat = NFS3ERR_IO
        except XdrError:
            raise
        except Exception:
            log.exception("nfs3 proc %d failed", proc)
            stat = NFS3ERR_SERVERFAULT
        pk = Packer()
        pk.uint32(stat)
        for _ in range(self.V3_FAIL_SHAPE.get(proc, 0)):
            pk.uint32(0)                 # attributes_follow = FALSE
        return pk.get()

    def _v3_fh(self, up):
        return fh_ino(up.opaque(NFS3_FHSIZE))

    @staticmethod
    def _v3_ftype(st_mode):
        if statmod.S_ISDIR(st_mode):
            return NF3DIR
        if statmod.S_ISLNK(st_mode):
            return NF3LNK
        if statmod.S_ISCHR(st_mode):
            return NF3CHR
        if statmod.S_ISBLK(st_mode):
            return NF3BLK
        if statmod.S_ISFIFO(st_mode):
            return NF3FIFO
        if statmod.S_ISSOCK(st_mode):
            return NF3SOCK
        return NF3REG

    @staticmethod
    def _nfstime3(pk, t_ns):
        pk.uint32((t_ns // 10**9) & 0xFFFFFFFF)
        pk.uint32(t_ns % 10**9)

    def _pack_fattr3(self, pk, ino, path, st):
        uid, gid, mode = self.file_ugm(ino, path, st)
        pk.uint32(self._v3_ftype(st.st_mode))
        pk.uint32(mode & 0o7777)
        pk.uint32(st.st_nlink)
        pk.uint32(uid)
        pk.uint32(gid)
        pk.uint64(st.st_size)
        pk.uint64(getattr(st, "st_blocks", 0) * 512 or st.st_size)
        rdev = getattr(st, "st_rdev", 0)
        if rdev and hasattr(os, "major"):
            pk.uint32(os.major(rdev))
            pk.uint32(os.minor(rdev))
        else:
            pk.uint32(0)
            pk.uint32(0)
        pk.uint64(FSID_MAJOR)
        pk.uint64(ino)
        self._nfstime3(pk, st.st_atime_ns)
        self._nfstime3(pk, st.st_mtime_ns)
        self._nfstime3(pk, self.change_of(st))
        return pk

    def _post_attr(self, pk, ino, path):
        """post_op_attr: TRUE + fattr3 when the object still stats."""
        try:
            st = os.lstat(path)
        except OSError:
            pk.boolean(False)
            return
        pk.boolean(True)
        self._pack_fattr3(pk, ino, path, st)

    @staticmethod
    def _wcc_snap(path):
        """Capture pre-op wcc_attr (size, mtime, ctime) of a path."""
        try:
            st = os.lstat(path)
            return (st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        except OSError:
            return None

    def _pack_wcc(self, pk, pre, ino, path):
        """wcc_data: pre_op_attr from a snapshot + live post_op_attr."""
        if pre is None:
            pk.boolean(False)
        else:
            pk.boolean(True)
            pk.uint64(pre[0])
            self._nfstime3(pk, pre[1])
            self._nfstime3(pk, pre[2])
        self._post_attr(pk, ino, path)

    def _decode_sattr3(self, up):
        """Decode sattr3 into the apply_attrs vals dict."""
        vals = {}
        if up.boolean():
            vals["mode"] = up.uint32() & 0o7777
        if up.boolean():
            vals["uid"] = up.uint32()
        if up.boolean():
            vals["gid"] = up.uint32()
        if up.boolean():
            vals["size"] = up.uint64()
        for key in ("atime_ns", "mtime_ns"):
            how = up.uint32()
            if how == SET_TO_CLIENT_TIME:
                sec = up.uint32()
                nsec = up.uint32()
                if nsec >= 10**9:
                    raise NfsErr(NFS3ERR_INVAL)
                vals[key] = sec * 10**9 + nsec
            elif how == SET_TO_SERVER_TIME:
                vals[key] = "now"
            elif how != DONT_CHANGE:
                raise NfsErr(NFS3ERR_INVAL)
        return vals

    # -- NFSv3 procedures --------------------------------------------------
    def v3_getattr(self, ctx, up):
        ino = self._v3_fh(up)
        path = self.path_of(ino)
        st = self.lstat(path)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_fattr3(pk, ino, path, st)
        return pk.get()

    def v3_setattr(self, ctx, up):
        ino = self._v3_fh(up)
        vals = self._decode_sattr3(up)
        guard = up.boolean()
        guard_ctime = None
        if guard:
            guard_ctime = (up.uint32(), up.uint32())
        path = self.path_of(ino)
        pre = self._wcc_snap(path)
        if guard:
            st = self.lstat(path)
            ct = self.change_of(st)
            if (ct // 10**9, ct % 10**9) != guard_ctime:
                raise NfsErr(NFS3ERR_NOT_SYNC)
        try:
            self.apply_attrs(ino, path, vals)
        except OSError as e:
            raise NfsErr(oserror_to_stat(e))
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_wcc(pk, pre, ino, path)
        return pk.get()

    def v3_lookup(self, ctx, up):
        dir_ino = self._v3_fh(up)
        name = up.string(MNTPATHLEN)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        if not os.path.lexists(path):
            pk = Packer()
            pk.uint32(NFS3ERR_NOENT)
            self._post_attr(pk, dir_ino, dpath)
            return pk.get()
        ino = self.imap.get_or_alloc(dir_ino, name)
        pk = Packer()
        pk.uint32(NFS3_OK)
        pk.opaque(fh_bytes(ino))
        self._post_attr(pk, ino, path)
        self._post_attr(pk, dir_ino, dpath)
        return pk.get()

    def v3_access(self, ctx, up):
        ino = self._v3_fh(up)
        want = up.uint32()
        path = self.path_of(ino)
        st = self.lstat(path)
        uid, gid, mode = self.file_ugm(ino, path, st)
        can_r = self.check_access(ctx, st, uid, gid, mode, True, False, False)
        can_w = (not self.read_only
                 and self.check_access(ctx, st, uid, gid, mode,
                                       False, True, False))
        can_x = self.check_access(ctx, st, uid, gid, mode, False, False, True)
        granted = 0
        if can_r:
            granted |= ACCESS3_READ
        if can_w:
            granted |= ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE
        if can_x:
            granted |= ACCESS3_EXECUTE | ACCESS3_LOOKUP
        if not statmod.S_ISDIR(st.st_mode):
            granted &= ~(ACCESS3_LOOKUP | ACCESS3_DELETE)
        else:
            granted &= ~ACCESS3_EXECUTE
        pk = Packer()
        pk.uint32(NFS3_OK)
        pk.boolean(True)
        self._pack_fattr3(pk, ino, path, st)
        pk.uint32(granted & want)
        return pk.get()

    def v3_readlink(self, ctx, up):
        ino = self._v3_fh(up)
        path = self.path_of(ino)
        st = self.lstat(path)
        if not statmod.S_ISLNK(st.st_mode):
            raise NfsErr(NFS3ERR_INVAL)
        target = os.readlink(path)
        pk = Packer()
        pk.uint32(NFS3_OK)
        pk.boolean(True)
        self._pack_fattr3(pk, ino, path, st)
        pk.string(target)
        return pk.get()

    def v3_read(self, ctx, up):
        ino = self._v3_fh(up)
        offset = up.uint64()
        count = up.uint32()
        path = self.path_of(ino)
        self._require_regular(path)
        # a UDP reply must fit one datagram, whatever count the client asks
        count = min(count, MAXIO_UDP if ctx.transport == "udp" else MAXIO)
        e = self.cache.get(ino, path, False)
        size = FileCache.size(e)
        if offset >= size:
            data = b""
        else:
            data = FileCache.pread(e, count, offset)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, ino, path)
        pk.uint32(len(data))
        pk.boolean(offset + len(data) >= size)
        pk.opaque(data)
        return pk.get()

    def v3_write(self, ctx, up):
        ino = self._v3_fh(up)
        offset = up.uint64()
        count = up.uint32()
        stable = up.uint32()
        data = up.opaque()
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        path = self.path_of(ino)
        self._require_regular(path)
        pre = self._wcc_snap(path)
        e = self.cache.get(ino, path, True)
        n = FileCache.pwrite(e, data[:count], offset)
        if stable != UNSTABLE:
            FileCache.fsync(e)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_wcc(pk, pre, ino, path)
        pk.uint32(n)
        pk.uint32(stable if stable != UNSTABLE else UNSTABLE)
        pk.opaque_fixed(self.write_verf)
        return pk.get()

    def _v3_new_object(self, dir_ino, name, path, ino, pre, dpath):
        """Shared CREATE/MKDIR/SYMLINK/MKNOD success reply tail."""
        pk = Packer()
        pk.uint32(NFS3_OK)
        pk.boolean(True)                 # post_op_fh3 handle_follows
        pk.opaque(fh_bytes(ino))
        self._post_attr(pk, ino, path)
        self._pack_wcc(pk, pre, dir_ino, dpath)
        return pk.get()

    def v3_create(self, ctx, up):
        dir_ino = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        mode3 = up.uint32()
        cverf = None
        vals = {}
        if mode3 in (UNCHECKED, GUARDED):
            vals = self._decode_sattr3(up)
        elif mode3 == EXCLUSIVE:
            cverf = up.opaque_fixed(NFS3_CREATEVERFSIZE)
        else:
            raise NfsErr(NFS3ERR_INVAL)
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        pre = self._wcc_snap(dpath)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        existed = os.path.lexists(path)
        if mode3 == EXCLUSIVE:
            ino0 = self.imap.get_child(dir_ino, name)
            if existed:
                if (self.excl_verfs.get(ino0) if ino0 else None) != cverf:
                    raise NfsErr(NFS3ERR_EXIST)
            else:
                fd = os.open(path, flags | os.O_EXCL, 0o644)
                os.close(fd)
                ino0 = self.imap.get_or_alloc(dir_ino, name)
                self.excl_verfs[ino0] = cverf
                self._chown_new(path, ctx, ino0)
        else:
            if mode3 == GUARDED:
                flags |= os.O_EXCL
            try:
                fd = os.open(path, flags, vals.get("mode", 0o644))
                os.close(fd)
            except FileExistsError:
                raise NfsErr(NFS3ERR_EXIST)
            ino0 = self.imap.get_or_alloc(dir_ino, name)
            if not existed:
                if vals:
                    try:
                        self.apply_attrs(ino0, path, vals)
                    except OSError:
                        pass
                self._chown_new(path, ctx, ino0)
            elif mode3 == UNCHECKED and vals.get("size") == 0:
                self.apply_attrs(ino0, path, {"size": 0})
        ino = self.imap.get_or_alloc(dir_ino, name)
        return self._v3_new_object(dir_ino, name, path, ino, pre, dpath)

    def v3_mkdir(self, ctx, up):
        dir_ino = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        vals = self._decode_sattr3(up)
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        pre = self._wcc_snap(dpath)
        try:
            os.mkdir(path, vals.get("mode", 0o755))
        except FileExistsError:
            raise NfsErr(NFS3ERR_EXIST)
        ino = self.imap.get_or_alloc(dir_ino, name)
        if vals:
            try:
                self.apply_attrs(ino, path, vals)
            except OSError:
                pass
        self._chown_new(path, ctx, ino)
        return self._v3_new_object(dir_ino, name, path, ino, pre, dpath)

    def v3_symlink(self, ctx, up):
        dir_ino = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        vals = self._decode_sattr3(up)
        target = up.string(MNTPATHLEN)
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        if not self.symlink_ok:
            raise NfsErr(NFS3ERR_NOTSUPP)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        pre = self._wcc_snap(dpath)
        try:
            os.symlink(target, path)
        except FileExistsError:
            raise NfsErr(NFS3ERR_EXIST)
        ino = self.imap.get_or_alloc(dir_ino, name)
        self._chown_new(path, ctx, ino)
        return self._v3_new_object(dir_ino, name, path, ino, pre, dpath)

    def v3_mknod(self, ctx, up):
        dir_ino = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        ftype = up.uint32()
        dev_major = dev_minor = 0
        vals = {}
        if ftype in (NF3CHR, NF3BLK):
            vals = self._decode_sattr3(up)
            dev_major = up.uint32()
            dev_minor = up.uint32()
        elif ftype in (NF3SOCK, NF3FIFO):
            vals = self._decode_sattr3(up)
        else:
            raise NfsErr(NFS3ERR_BADTYPE)
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        pre = self._wcc_snap(dpath)
        try:
            if ftype == NF3FIFO and hasattr(os, "mkfifo"):
                os.mkfifo(path, vals.get("mode", 0o644))
            elif ftype == NF3SOCK and hasattr(os, "mknod"):
                os.mknod(path, vals.get("mode", 0o644) | statmod.S_IFSOCK)
            elif ftype in (NF3CHR, NF3BLK) and hasattr(os, "mknod"):
                kind = statmod.S_IFCHR if ftype == NF3CHR else statmod.S_IFBLK
                os.mknod(path, vals.get("mode", 0o644) | kind,
                         os.makedev(dev_major, dev_minor))
            else:
                raise NfsErr(NFS3ERR_NOTSUPP)
        except FileExistsError:
            raise NfsErr(NFS3ERR_EXIST)
        except PermissionError:
            raise NfsErr(NFS3ERR_PERM)
        ino = self.imap.get_or_alloc(dir_ino, name)
        self._chown_new(path, ctx, ino)
        return self._v3_new_object(dir_ino, name, path, ino, pre, dpath)

    def _v3_remove_common(self, up, want_dir):
        dir_ino = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        dpath = self.dir_path_of(dir_ino)
        path = self.child_path(dir_ino, name)
        pre = self._wcc_snap(dpath)
        st = self.lstat(path)
        isdir = statmod.S_ISDIR(st.st_mode)
        if want_dir and not isdir:
            raise NfsErr(NFS3ERR_NOTDIR)
        if not want_dir and isdir:
            raise NfsErr(NFS3ERR_ISDIR)
        ino = self.imap.get_child(dir_ino, name)
        if ino:
            self.cache.invalidate(ino)
            self.side.forget(ino)
        if isdir:
            os.rmdir(path)
        else:
            os.unlink(path)
        self.imap.remove_child(dir_ino, name)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_wcc(pk, pre, dir_ino, dpath)
        return pk.get()

    def v3_remove(self, ctx, up):
        return self._v3_remove_common(up, want_dir=False)

    def v3_rmdir(self, ctx, up):
        return self._v3_remove_common(up, want_dir=True)

    def v3_rename(self, ctx, up):
        from_dir = self._v3_fh(up)
        from_name = valid_name(up.string(MNTPATHLEN))
        to_dir = self._v3_fh(up)
        to_name = valid_name(up.string(MNTPATHLEN))
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        fdpath = self.dir_path_of(from_dir)
        tdpath = self.dir_path_of(to_dir)
        src = self.child_path(from_dir, from_name)
        dst = self.child_path(to_dir, to_name)
        pre_f = self._wcc_snap(fdpath)
        pre_t = self._wcc_snap(tdpath)
        if not os.path.lexists(src):
            raise NfsErr(NFS3ERR_NOENT)
        moving = self.imap.get_child(from_dir, from_name)
        if moving:
            self.cache.invalidate(moving)
        replaced0 = self.imap.get_child(to_dir, to_name)
        if replaced0:
            self.cache.invalidate(replaced0)
            self.side.forget(replaced0)
        try:
            os.replace(src, dst)
        except IsADirectoryError:
            raise NfsErr(NFS3ERR_EXIST)
        except OSError as e:
            # renaming a directory over an existing empty directory
            if os.path.isdir(src) and os.path.isdir(dst):
                os.rmdir(dst)
                os.rename(src, dst)
            else:
                raise NfsErr(oserror_to_stat(e))
        self.imap.move(from_dir, from_name, to_dir, to_name)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_wcc(pk, pre_f, from_dir, fdpath)
        self._pack_wcc(pk, pre_t, to_dir, tdpath)
        return pk.get()

    def v3_link(self, ctx, up):
        ino = self._v3_fh(up)
        link_dir = self._v3_fh(up)
        name = valid_name(up.string(MNTPATHLEN))
        if self.read_only:
            raise NfsErr(NFS3ERR_ROFS)
        src = self.path_of(ino)
        if statmod.S_ISDIR(self.lstat(src).st_mode):
            raise NfsErr(NFS3ERR_ISDIR)
        dpath = self.dir_path_of(link_dir)
        dst = self.child_path(link_dir, name)
        pre = self._wcc_snap(dpath)
        try:
            os.link(src, dst)
        except FileExistsError:
            raise NfsErr(NFS3ERR_EXIST)
        except AttributeError:
            raise NfsErr(NFS3ERR_NOTSUPP)
        self.imap.get_or_alloc(link_dir, name)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, ino, src)
        self._pack_wcc(pk, pre, link_dir, dpath)
        return pk.get()

    def _v3_dir_entries(self, dir_ino, dpath, cookie):
        """Sorted entries after the given cookie: (cookie, name, ino)."""
        try:
            names = sorted(os.listdir(dpath))
        except NotADirectoryError:
            raise NfsErr(NFS3ERR_NOTDIR)
        out = []
        for i, name in enumerate(names):
            this_cookie = i + 3          # cookies 0,1,2 are reserved
            if this_cookie <= cookie:
                continue
            out.append((this_cookie, name))
        return out

    def v3_readdir(self, ctx, up):
        dir_ino = self._v3_fh(up)
        cookie = up.uint64()
        up.opaque_fixed(NFS3_COOKIEVERFSIZE)   # cookieverf: we use zeros
        count = up.uint32()
        dpath = self.dir_path_of(dir_ino)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, dir_ino, dpath)
        pk.opaque_fixed(b"\0" * NFS3_COOKIEVERFSIZE)
        used = len(pk.get()) + 16
        eof = True
        for this_cookie, name in self._v3_dir_entries(dir_ino, dpath, cookie):
            ino = self.imap.get_or_alloc(dir_ino, name)
            eb = Packer()
            eb.boolean(True)
            eb.uint64(ino)
            eb.string(name)
            eb.uint64(this_cookie)
            b = eb.get()
            if used + len(b) + 8 > count:
                eof = False
                break
            pk.raw(b)
            used += len(b)
        pk.boolean(False)                # end of entry list
        pk.boolean(eof)
        return pk.get()

    def v3_readdirplus(self, ctx, up):
        dir_ino = self._v3_fh(up)
        cookie = up.uint64()
        up.opaque_fixed(NFS3_COOKIEVERFSIZE)
        dircount = up.uint32()
        maxcount = up.uint32()
        dpath = self.dir_path_of(dir_ino)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, dir_ino, dpath)
        pk.opaque_fixed(b"\0" * NFS3_COOKIEVERFSIZE)
        used = len(pk.get()) + 16
        dused = 0
        eof = True
        for this_cookie, name in self._v3_dir_entries(dir_ino, dpath, cookie):
            cpath = os.path.join(dpath, name)
            ino = self.imap.get_or_alloc(dir_ino, name)
            eb = Packer()
            eb.boolean(True)
            eb.uint64(ino)
            eb.string(name)
            eb.uint64(this_cookie)
            self._post_attr(eb, ino, cpath)
            eb.boolean(True)             # post_op_fh3 handle_follows
            eb.opaque(fh_bytes(ino))
            b = eb.get()
            nb = 8 + 8 + 4 + len(name)
            if (used + len(b) + 8 > maxcount
                    or (dircount and dused + nb > dircount)):
                eof = False
                break
            pk.raw(b)
            used += len(b)
            dused += nb
        pk.boolean(False)
        pk.boolean(eof)
        return pk.get()

    def v3_fsstat(self, ctx, up):
        ino = self._v3_fh(up)
        path = self.path_of(ino)
        s = self.fs_stats()
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, ino, path)
        pk.uint64(s["space_total"])
        pk.uint64(s["space_free"])
        pk.uint64(s["space_avail"])
        pk.uint64(s["files_total"])
        pk.uint64(s["files_free"])
        pk.uint64(s["files_avail"])
        pk.uint32(0)                     # invarsec
        return pk.get()

    def v3_fsinfo(self, ctx, up):
        ino = self._v3_fh(up)
        path = self.path_of(ino)
        # over UDP a whole READ/WRITE must fit one 64 KiB datagram
        io_max = MAXIO_UDP if ctx.transport == "udp" else MAXIO
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, ino, path)
        pk.uint32(io_max)                # rtmax
        pk.uint32(io_max)                # rtpref
        pk.uint32(4096)                  # rtmult
        pk.uint32(io_max)                # wtmax
        pk.uint32(io_max)                # wtpref
        pk.uint32(4096)                  # wtmult
        pk.uint32(65536)                 # dtpref
        pk.uint64(NFS4_INT64_MAX)        # maxfilesize
        pk.uint32(0)                     # time_delta seconds
        pk.uint32(1)                     # time_delta nseconds
        props = FSF3_LINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME
        if self.symlink_ok:
            props |= FSF3_SYMLINK
        pk.uint32(props)
        return pk.get()

    def v3_pathconf(self, ctx, up):
        ino = self._v3_fh(up)
        path = self.path_of(ino)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._post_attr(pk, ino, path)
        pk.uint32(255)                   # linkmax
        pk.uint32(255)                   # name_max
        pk.boolean(True)                 # no_trunc
        pk.boolean(True)                 # chown_restricted
        pk.boolean(IS_WINDOWS)           # case_insensitive
        pk.boolean(True)                 # case_preserving
        return pk.get()

    def v3_commit(self, ctx, up):
        ino = self._v3_fh(up)
        up.uint64()                      # offset
        up.uint32()                      # count
        path = self.path_of(ino)
        self._require_regular(path)
        pre = self._wcc_snap(path)
        if not self.read_only:
            e = self.cache.get(ino, path, True)
            FileCache.fsync(e)
        pk = Packer()
        pk.uint32(NFS3_OK)
        self._pack_wcc(pk, pre, ino, path)
        pk.opaque_fixed(self.write_verf)
        return pk.get()

    # -- MOUNT v3 procedures (RFC 1813 sec 5) --------------------------------
    def mnt3_null(self, ctx, up):
        return b""

    def mnt3_mnt(self, ctx, up):
        dirpath = up.string(MNTPATHLEN)
        pk = Packer()
        if dirpath not in ("/", ""):
            pk.uint32(MNT3ERR_NOENT)
            return pk.get()
        pk.uint32(MNT3_OK)
        pk.opaque(fh_bytes(ROOT_INO))    # fhandle3
        pk.uint32(2)                     # auth_flavors<>
        pk.uint32(AUTH_SYS)
        pk.uint32(AUTH_NONE)
        return pk.get()

    def mnt3_dump(self, ctx, up):
        pk = Packer()
        pk.boolean(False)                # empty mountlist
        return pk.get()

    def mnt3_umnt(self, ctx, up):
        up.string(MNTPATHLEN)            # dirpath
        return b""

    def mnt3_export(self, ctx, up):
        pk = Packer()
        pk.boolean(True)                 # one exportnode
        pk.string("/")                   # ex_dir
        pk.boolean(False)                # no groups
        pk.boolean(False)                # no next entry
        return pk.get()


# ---------------------------------------------------------------------------
# fattr4 attribute encoders (GETATTR / READDIR / VERIFY)
# ---------------------------------------------------------------------------

class _AttrSrc(object):
    __slots__ = ("srv", "ino", "path", "st", "_vfs", "_ugm", "minor")

    def __init__(self, srv, ino, path, st, minor=0):
        self.srv = srv
        self.ino = ino
        self.path = path
        self.st = st
        self._vfs = None
        self._ugm = None
        self.minor = minor

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
        pk.raw(pack_bitmap(src.srv.supported_for(src.minor)))

    @reg(FATTR4_SUPPATTR_EXCLCREAT)
    def _exclcreat(src, pk):
        # NFSv4.1 REQUIRED attr (RFC 5661 sec 5.8.1.14): attrs a client may
        # set in an EXCLUSIVE4_1 create
        pk.raw(pack_bitmap(src.srv.exclcreat_attrs))

    @reg(FATTR4_XATTR_SUPPORT)
    def _xattr_support(src, pk):
        # RFC 8276 sec 8.2.1: does this object support extended attributes
        pk.boolean(src.srv.xattr_ok
                   and not statmod.S_ISLNK(src.st.st_mode))

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


class UdpHandler(socketserver.BaseRequestHandler):
    """One RPC call per datagram: record marking is for stream transports
    only (RFC 5531 sec 11), so the datagram body IS the RPC message.
    Serves the portmapper (BSD mount_nfs sends GETPORT over UDP) and
    NFSv3 + MOUNT for clients mounting with proto=udp/mountproto=udp."""

    def handle(self):
        data, sock = self.request
        # duplicate-request cache: UDP clients retransmit, and replaying a
        # non-idempotent v3 op (REMOVE, exclusive CREATE, RENAME) from the
        # cache is the only correct answer for a lost reply
        drc = self.server.drc
        key = None
        if len(data) >= 4:
            key = (self.client_address, data[0:4])
            with self.server.drc_lock:
                cached = drc.get(key)
            if cached is not None and cached[0] == data:
                self._send(sock, cached[1])
                return
        try:
            reply = self.server.nfs.handle_rpc(data, transport="udp")
        except Exception as e:
            log.info("udp %s dropped: %s", self.client_address, e)
            return
        if reply is None:
            return
        if key is not None:
            with self.server.drc_lock:
                drc[key] = (data, reply)
                while len(drc) > UDP_DRC_SIZE:
                    drc.pop(next(iter(drc)))
        self._send(sock, reply)

    def _send(self, sock, reply):
        try:
            sock.sendto(reply, self.client_address)
        except OSError as e:
            log.info("udp reply to %s failed: %s", self.client_address, e)


class UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    # the socketserver default of 8 KiB would truncate a 32 KiB v3 WRITE
    max_packet_size = 65536

    def __init__(self, *args, **kw):
        socketserver.ThreadingUDPServer.__init__(self, *args, **kw)
        self.drc = {}                # (addr, xid) -> (request, reply)
        self.drc_lock = threading.Lock()


def _serve_in_thread(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t


def start_pmap_servers(nfs, bind, pmap_port, out=None,
                       tcp_cls=None, udp_cls=None):
    """Bind the portmapper listeners, tcp AND udp (BSD mount_nfs sends its
    GETPORT queries over UDP even for -T/TCP mounts, while some clients
    query over TCP).

    When binding a SPECIFIC address raises PermissionError, retry on the
    wildcard: macOS 10.14+ allows unprivileged binds below port 1024 ONLY
    on the wildcard address; a specific bind (e.g. 127.0.0.1) still needs
    root there. The portmapper only reveals port numbers, so the wildcard
    fallback exposes nothing that matters -- the NFS service itself stays
    on the requested bind address.

    Returns a list of (server, proto) for the listeners that came up; a
    listener that cannot bind at all is reported on `out` and skipped.
    tcp_cls/udp_cls exist for tests (they default to Server/UdpServer)."""
    if out is None:
        out = sys.stdout
    if tcp_cls is None:
        tcp_cls = Server
    if udp_cls is None:
        udp_cls = UdpServer

    def pmap_bind(cls, handler, bind_addr):
        ps = cls((bind_addr, pmap_port), handler, bind_and_activate=False)
        if ":" in bind_addr:
            ps.address_family = socket.AF_INET6
            ps.socket = socket.socket(ps.address_family, ps.socket_type)
        try:
            ps.server_bind()
            ps.server_activate()
        except OSError:
            ps.server_close()
            raise
        return ps

    servers = []
    for cls, handler, proto in ((tcp_cls, ConnHandler, "tcp"),
                                (udp_cls, UdpHandler, "udp")):
        ps = None
        try:
            ps = pmap_bind(cls, handler, bind)
        except OSError as e:
            if (isinstance(e, PermissionError)
                    and bind not in ("", "0.0.0.0", "::")):
                try:
                    ps = pmap_bind(cls, handler, "0.0.0.0")
                    out.write(
                        "portmapper: %s port %d bound on 0.0.0.0"
                        " (binding %s needs root on this platform)\n"
                        % (proto, pmap_port, bind))
                except OSError as e2:
                    e = e2
                    ps = None
            if ps is None:
                out.write(
                    "portmapper: cannot bind %s port %d (%s);"
                    " v3 clients relying on the portmapper"
                    " will not find the server\n"
                    % (proto, pmap_port, e))
                continue
        ps.nfs = nfs
        servers.append((ps, proto))
    return servers


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nfsd.py",
        description="cross-platform user-space NFS server"
                    " (v3, v4.0, v4.1, v4.2; pure Python)")
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
    ap.add_argument("-vers", choices=("3", "4"), default=None,
                    help="serve only this NFS major version: 3 (NFSv3 +"
                         " MOUNT) or 4 (NFSv4.0/4.1/4.2); default: all")
    ap.add_argument("-pmap", action="store_true",
                    help="also serve portmapper v2 (RFC 1833) on port 111"
                         " tcp+udp, for NFSv3 clients without a mountport="
                         " mount option (OpenBSD, NetBSD, DragonFly)")
    ap.add_argument("-pmap-port", type=int, default=PMAP_PORT, metavar="PORT",
                    help="portmapper port (default %d)" % PMAP_PORT)
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

    versions = (3, 4) if args.vers is None else (int(args.vers),)
    nfs = NfsServer(root, args.port, read_only=args.ro, lease=args.lease,
                    anon_uid=args.anonuid, anon_gid=args.anongid,
                    versions=versions)

    srv = Server((args.bind, args.port), ConnHandler,
                 bind_and_activate=False)
    if ":" in args.bind:
        srv.address_family = socket.AF_INET6
        srv.socket = socket.socket(srv.address_family, srv.socket_type)
    srv.server_bind()
    srv.server_activate()
    srv.nfs = nfs

    usrv = None
    if 3 in versions:
        # NFSv3 + MOUNT also answer over UDP on the same port (classic v3
        # clients and the BSDs default to it); v4 stays TCP-only
        try:
            usrv = UdpServer((args.bind, args.port), UdpHandler,
                             bind_and_activate=False)
            if ":" in args.bind:
                usrv.address_family = socket.AF_INET6
                usrv.socket = socket.socket(usrv.address_family,
                                            usrv.socket_type)
            usrv.server_bind()
            usrv.server_activate()
            usrv.nfs = nfs
            nfs.udp_enabled = True
        except OSError as e:
            sys.stdout.write("udp: cannot bind port %d (%s); NFSv3 over"
                             " udp disabled\n" % (args.port, e))
            usrv = None

    pmap_srvs = []
    if args.pmap:
        pmap_srvs = start_pmap_servers(nfs, args.bind, args.pmap_port)

    vlabel = {(3,): "v3", (4,): "v4.0/v4.1/v4.2",
              (3, 4): "v3/v4.0/v4.1/v4.2"}[tuple(sorted(versions))]
    sys.stdout.write("nfsd.py: exporting %s on port %d/tcp%s (%s, %s)\n"
                     % (root, args.port,
                        "+udp" if usrv is not None else "",
                        "read-only" if args.ro else "read-write", vlabel))
    if 4 in versions:
        sys.stdout.write("mount with: mount -t nfs -o"
                         " vers=4.2,port=%d,proto=tcp HOST:/ /mnt/x\n"
                         % args.port)
    else:
        sys.stdout.write("mount with: mount -t nfs -o vers=3,port=%d,"
                         "mountport=%d,mountproto=tcp,proto=tcp,nolock"
                         " HOST:/ /mnt/x\n" % (args.port, args.port))
    if pmap_srvs:
        sys.stdout.write("portmapper v2 on port %d (%s): v3 clients can"
                         " mount without port options\n"
                         % (args.pmap_port,
                            "+".join(proto for _, proto in pmap_srvs)))
    sys.stdout.flush()
    try:
        for ps, _ in pmap_srvs:
            _serve_in_thread(ps)
        if usrv is not None:
            _serve_in_thread(usrv)
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for ps, _ in pmap_srvs:
            ps.server_close()
        if usrv is not None:
            usrv.server_close()
        srv.server_close()
        nfs.cache.close_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
