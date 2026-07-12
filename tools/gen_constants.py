#!/usr/bin/env python3
"""Machine-extract protocol constants from the IETF specs into Python.

Sources (downloaded verbatim into spec/):
  - RFC 7531: NFSv4.0 external data representation (XDR) description.
    The XDR is embedded in lines prefixed with "///" (code-extraction format).
  - RFC 5531: ONC RPC v2 protocol specification (msg_type, reply_stat,
    accept_stat, reject_stat, auth_stat, auth_flavor enums).

Every const, enum, and the program/version/procedure declaration is extracted
mechanically -- nothing is typed from memory -- so the generated values are
exactly the spec's values.

Usage:
  python3 tools/gen_constants.py                  # write block to stdout
  python3 tools/gen_constants.py --splice nfsd.py # replace between markers
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, os.pardir, "spec")

BEGIN = "# === BEGIN GENERATED CONSTANTS (tools/gen_constants.py; DO NOT EDIT) ==="
END = "# === END GENERATED CONSTANTS ==="

RFC5531_ENUM_WHITELIST = (
    "msg_type",
    "reply_stat",
    "accept_stat",
    "reject_stat",
    "auth_stat",
    "auth_flavor",
)


def load(name):
    path = os.path.join(SPEC, name)
    with open(path, "r", encoding="ascii", errors="replace") as f:
        return f.read()


def extract_rfc7531_xdr(text):
    """Strip the '///' code-extraction prefix to recover the pure .x file."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*///( ?)(.*)$", line)
        if m:
            out.append(m.group(2))
    return "\n".join(out)


def clean_rfc5531(text):
    """Drop page furniture (form feeds, running headers/footers)."""
    out = []
    for line in text.splitlines():
        if "\f" in line:
            continue
        if re.match(r"^\s*Thurlow\b", line):
            continue
        if re.match(r"^\s*RFC 5531\b", line):
            continue
        out.append(line)
    return "\n".join(out)


def strip_comments(x):
    return re.sub(r"/\*.*?\*/", "", x, flags=re.S)


def parse_consts(x):
    return [
        (n, int(v, 0))
        for n, v in re.findall(
            r"\bconst\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;", x
        )
    ]


def parse_enums(x):
    res = []
    for name, body in re.findall(r"\benum\s+(\w+)\s*\{(.*?)\}\s*;", x, flags=re.S):
        entries = [
            (n, int(v, 0))
            for n, v in re.findall(r"(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)", body)
        ]
        res.append((name, entries))
    return res


def parse_programs(x):
    """Parse every: program NAME { version NAME { procs } = V; } = P;

    RFC 7531 declares TWO programs (NFS4_PROGRAM and the NFS4_CALLBACK
    program), so this must match each one non-greedily. A program's closing
    brace sits at column 0 of the recovered .x text, the version's is
    indented.
    """
    out = []
    for m in re.finditer(
        r"^program\s+(\w+)\s*\{(.*?)^\}\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
        x,
        flags=re.S | re.M,
    ):
        prog_name, body, prog_num = m.group(1), m.group(2), int(m.group(3), 0)
        vm = re.search(
            r"\bversion\s+(\w+)\s*\{(.*?)\}\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
            body,
            flags=re.S,
        )
        vers_name, vbody, vers_num = vm.group(1), vm.group(2), int(vm.group(3), 0)
        procs = [
            (n, int(v))
            for n, v in re.findall(r"(\w+)\s*\(\w+\)\s*=\s*(\d+)\s*;", vbody)
        ]
        out.append((prog_name, prog_num, vers_name, vers_num, procs))
    return out


def emit():
    lines = [BEGIN]
    lines.append("# Machine-extracted from the IETF specifications:")
    lines.append("#   RFC 7531 (NFSv4.0 XDR)  -> spec/rfc7531.txt")
    lines.append("#   RFC 5531 (ONC RPC v2)   -> spec/rfc5531.txt")
    lines.append("# Regenerate with: python3 tools/gen_constants.py --splice nfsd.py")
    seen = {}

    def add(name, value, origin):
        if name in seen:
            if seen[name] != value:
                raise SystemExit(
                    "conflict: %s = %r vs %r" % (name, seen[name], value)
                )
            return
        seen[name] = value
        lines.append("%s = %d" % (name, value))

    x4 = strip_comments(extract_rfc7531_xdr(load("rfc7531.txt")))

    lines.append("")
    lines.append("# --- RFC 7531 top-level consts ---")
    for n, v in parse_consts(x4):
        add(n, v, "rfc7531")

    enums4 = parse_enums(x4)
    for name, entries in enums4:
        lines.append("")
        lines.append("# --- RFC 7531 enum %s ---" % name)
        for n, v in entries:
            add(n, v, "rfc7531")

    for prog_name, prog_num, vers_name, vers_num, procs in parse_programs(x4):
        lines.append("")
        lines.append("# --- RFC 7531 program declaration: %s ---" % prog_name)
        add(prog_name, prog_num, "rfc7531")
        add(vers_name, vers_num, "rfc7531")
        for n, v in procs:
            add(n, v, "rfc7531")

    x5 = strip_comments(clean_rfc5531(load("rfc5531.txt")))
    for name, entries in parse_enums(x5):
        if name not in RFC5531_ENUM_WHITELIST:
            continue
        lines.append("")
        lines.append("# --- RFC 5531 enum %s ---" % name)
        for n, v in entries:
            add(n, v, "rfc5531")

    # Reverse-lookup maps for logging.
    for enum_name, py_name in (("nfsstat4", "NFSSTAT4_NAMES"),
                               ("nfs_opnum4", "OP_NAMES")):
        for name, entries in enums4:
            if name == enum_name:
                lines.append("")
                lines.append("%s = {" % py_name)
                for n, v in entries:
                    lines.append("    %d: %r," % (v, n))
                lines.append("}")

    lines.append(END)
    return "\n".join(lines) + "\n"


def main():
    block = emit()
    if len(sys.argv) >= 3 and sys.argv[1] == "--splice":
        target = sys.argv[2]
        with open(target, "r", encoding="ascii") as f:
            src = f.read()
        b = src.index(BEGIN)
        e = src.index(END) + len(END) + 1
        with open(target, "w", encoding="ascii", newline="\n") as f:
            f.write(src[:b] + block + src[e:])
        n = block.count("\n")
        sys.stdout.write("spliced %d lines into %s\n" % (n, target))
    else:
        sys.stdout.write(block)


if __name__ == "__main__":
    main()
