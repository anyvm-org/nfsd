#!/usr/bin/env python3
"""Machine-extract protocol constants from the IETF specs into Python.

Sources (downloaded verbatim into spec/):
  - RFC 7531: NFSv4.0 external data representation (XDR) description.
    The XDR is embedded in lines prefixed with "///" (code-extraction format).
  - RFC 5662: NFSv4.1 XDR description (same "///" format). A superset of the
    4.0 protocol: names already defined by RFC 7531 are checked for value
    equality (a mismatch aborts generation), and only 4.1-new names are
    emitted in the RFC 5662 sections.
  - RFC 7863: NFSv4.2 XDR description (same "///" format), a superset of
    4.1 in turn; handled exactly like RFC 5662 -- overlapping names are
    value-checked, only 4.2-new names are emitted.
  - RFC 5531: ONC RPC v2 protocol specification (msg_type, reply_stat,
    accept_stat, reject_stat, auth_stat, auth_flavor enums).
  - RFC 1813: NFS version 3 protocol. Its XDR is embedded as indented
    plain-text blocks (const/enum/program declarations parse with the
    same regexes once page furniture is stripped); the sec 2.4 size
    constants use a bare "NAME value" prose form with its own regex.
  - RFC 1833: ONC RPC binding protocols. Only the portmapper v2 pieces
    are emitted (PMAP_PROG program, PMAP_PORT, IPPROTO_TCP/UDP); the
    rpcbind v3/v4 protocol that shares the document is not served.

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


def extract_slashed_xdr(text):
    """Strip the '///' code-extraction prefix to recover the pure .x file.

    Both RFC 7531 (NFSv4.0) and RFC 5662 (NFSv4.1) embed their XDR this way.
    """
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


def clean_rfc1813(text):
    """Drop page furniture (form feeds, running headers/footers)."""
    out = []
    for line in text.splitlines():
        if "\f" in line:
            continue
        if re.match(r"^\s*Callaghan\b", line):
            continue
        if re.match(r"^\s*RFC 1813\b", line):
            continue
        out.append(line)
    return "\n".join(out)


def clean_rfc1833(text):
    """Drop page furniture (form feeds, running headers/footers)."""
    out = []
    for line in text.splitlines():
        if "\f" in line:
            continue
        if re.match(r"^\s*Srinivasan\b", line):
            continue
        if re.match(r"^\s*RFC 1833\b", line):
            continue
        out.append(line)
    return "\n".join(out)


# The only RFC 1833 constants nfsd.py needs: the portmapper's well-known
# port and the two transport protocol numbers used in mappings.
RFC1833_CONST_WHITELIST = ("PMAP_PORT", "IPPROTO_TCP", "IPPROTO_UDP")


def parse_rfc1813_sizes(text):
    """Extract the section 2.4 size constants (bare 'NAME value' form)."""
    return [
        (n, int(v))
        for n, v in re.findall(
            r"^   (NFS3_[A-Z0-9_]+)\s+(\d+)\s*$", text, flags=re.M
        )
    ]


def parse_rfc1813_programs(x):
    """Parse RFC 1813's indented single-version program declarations."""
    out = []
    for m in re.finditer(
        r"\bprogram\s+(\w+)\s*\{\s*version\s+(\w+)\s*\{(.*?)\}\s*=\s*(\d+)\s*;"
        r"\s*\}\s*=\s*(\d+)\s*;",
        x,
        flags=re.S,
    ):
        prog_name, vers_name, vbody = m.group(1), m.group(2), m.group(3)
        vers_num, prog_num = int(m.group(4)), int(m.group(5))
        procs = [
            (n, int(v))
            for n, v in re.findall(r"(\w+)\s*\(\w+\)\s*=\s*(\d+)\s*;", vbody)
        ]
        out.append((prog_name, prog_num, vers_name, vers_num, procs))
    return out


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
    lines.append("#   RFC 5662 (NFSv4.1 XDR)  -> spec/rfc5662.txt (4.1-new names only)")
    lines.append("#   RFC 5531 (ONC RPC v2)   -> spec/rfc5531.txt")
    lines.append("# Regenerate with: python3 tools/gen_constants.py --splice nfsd.py")
    seen = {}

    def check(name, value):
        """Record name=value; abort on a cross-spec value mismatch.

        Returns True when the name is new (should be emitted)."""
        if name in seen:
            if seen[name] != value:
                raise SystemExit(
                    "conflict: %s = %r vs %r" % (name, seen[name], value)
                )
            return False
        seen[name] = value
        return True

    def add(name, value, origin):
        if check(name, value):
            lines.append("%s = %d" % (name, value))

    x4 = strip_comments(extract_slashed_xdr(load("rfc7531.txt")))

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

    # RFC 5662 (NFSv4.1): same "///" embedding. Overlapping names are value
    # checked against RFC 7531 by check(); only 4.1-new names get emitted.
    x41 = strip_comments(extract_slashed_xdr(load("rfc5662.txt")))

    fresh = [(n, v) for n, v in parse_consts(x41) if n not in seen]
    if fresh:
        lines.append("")
        lines.append("# --- RFC 5662 top-level consts (NFSv4.1-new) ---")
    for n, v in parse_consts(x41):
        add(n, v, "rfc5662")

    enums41 = parse_enums(x41)
    for name, entries in enums41:
        fresh = [(n, v) for n, v in entries if n not in seen]
        # Value-check every entry (even dupes) so a 4.0/4.1 spec mismatch
        # aborts, but only open a section for enums that add new names.
        if fresh:
            lines.append("")
            lines.append("# --- RFC 5662 enum %s (NFSv4.1-new members) ---" % name)
        for n, v in entries:
            add(n, v, "rfc5662")

    for prog_name, prog_num, vers_name, vers_num, procs in parse_programs(x41):
        fresh = ([(prog_name, prog_num), (vers_name, vers_num)] + procs)
        fresh = [(n, v) for n, v in fresh if n not in seen]
        if fresh:
            lines.append("")
            lines.append("# --- RFC 5662 program declaration: %s ---" % prog_name)
        add(prog_name, prog_num, "rfc5662")
        add(vers_name, vers_num, "rfc5662")
        for n, v in procs:
            add(n, v, "rfc5662")

    # RFC 7863 (NFSv4.2): same "///" embedding, a superset of 4.1 in turn.
    x42 = strip_comments(extract_slashed_xdr(load("rfc7863.txt")))

    fresh = [(n, v) for n, v in parse_consts(x42) if n not in seen]
    if fresh:
        lines.append("")
        lines.append("# --- RFC 7863 top-level consts (NFSv4.2-new) ---")
    for n, v in parse_consts(x42):
        add(n, v, "rfc7863")

    enums42 = parse_enums(x42)
    for name, entries in enums42:
        fresh = [(n, v) for n, v in entries if n not in seen]
        if fresh:
            lines.append("")
            lines.append("# --- RFC 7863 enum %s (NFSv4.2-new members) ---" % name)
        for n, v in entries:
            add(n, v, "rfc7863")

    for prog_name, prog_num, vers_name, vers_num, procs in parse_programs(x42):
        fresh = ([(prog_name, prog_num), (vers_name, vers_num)] + procs)
        fresh = [(n, v) for n, v in fresh if n not in seen]
        if fresh:
            lines.append("")
            lines.append("# --- RFC 7863 program declaration: %s ---" % prog_name)
        add(prog_name, prog_num, "rfc7863")
        add(vers_name, vers_num, "rfc7863")
        for n, v in procs:
            add(n, v, "rfc7863")

    # RFC 1813 (NFSv3): indented plain-text XDR blocks.
    x3 = strip_comments(clean_rfc1813(load("rfc1813.txt")))

    lines.append("")
    lines.append("# --- RFC 1813 sec 2.4 size constants ---")
    for n, v in parse_rfc1813_sizes(x3):
        add(n, v, "rfc1813")

    fresh = [(n, v) for n, v in parse_consts(x3) if n not in seen]
    if fresh:
        lines.append("")
        lines.append("# --- RFC 1813 top-level consts ---")
    for n, v in parse_consts(x3):
        add(n, v, "rfc1813")

    for name, entries in parse_enums(x3):
        fresh = [(n, v) for n, v in entries if n not in seen]
        if fresh:
            lines.append("")
            lines.append("# --- RFC 1813 enum %s ---" % name)
        for n, v in entries:
            add(n, v, "rfc1813")

    for prog_name, prog_num, vers_name, vers_num, procs in \
            parse_rfc1813_programs(x3):
        lines.append("")
        lines.append("# --- RFC 1813 program declaration: %s ---" % prog_name)
        add(prog_name, prog_num, "rfc1813")
        add(vers_name, vers_num, "rfc1813")
        for n, v in procs:
            add(n, v, "rfc1813")

    # RFC 1833 (portmapper v2): same indented plain-text XDR as RFC 1813.
    # Only the PMAP program is served; the rpcbind v3/v4 protocol that
    # shares this document is skipped (its multi-version program block
    # would also defeat the single-version parser).
    xp = strip_comments(clean_rfc1833(load("rfc1833.txt")))
    lines.append("")
    lines.append("# --- RFC 1833 portmapper consts ---")
    for n, v in parse_consts(xp):
        if n in RFC1833_CONST_WHITELIST:
            add(n, v, "rfc1833")
    for prog_name, prog_num, vers_name, vers_num, procs in \
            parse_rfc1813_programs(xp):
        if prog_name != "PMAP_PROG":
            continue
        lines.append("")
        lines.append("# --- RFC 1833 program declaration: %s ---" % prog_name)
        add(prog_name, prog_num, "rfc1833")
        add(vers_name, vers_num, "rfc1833")
        for n, v in procs:
            add(n, v, "rfc1833")

    x5 = strip_comments(clean_rfc5531(load("rfc5531.txt")))
    for name, entries in parse_enums(x5):
        if name not in RFC5531_ENUM_WHITELIST:
            continue
        lines.append("")
        lines.append("# --- RFC 5531 enum %s ---" % name)
        for n, v in entries:
            add(n, v, "rfc5531")

    # Reverse-lookup maps for logging, merged across RFC 7531 + RFC 5662 +
    # RFC 7863 (each minor version's nfs_opnum4/nfsstat4 is a superset of
    # the previous one; identical values dedupe, mismatches abort).
    for enum_name, py_name in (("nfsstat4", "NFSSTAT4_NAMES"),
                               ("nfs_opnum4", "OP_NAMES")):
        merged = {}
        for name, entries in list(enums4) + list(enums41) + list(enums42):
            if name == enum_name:
                for n, v in entries:
                    if v in merged and merged[v] != n:
                        raise SystemExit(
                            "reverse-map conflict in %s: %d = %s vs %s"
                            % (enum_name, v, merged[v], n)
                        )
                    merged[v] = n
        lines.append("")
        lines.append("%s = {" % py_name)
        for v in sorted(merged):
            lines.append("    %d: %r," % (v, merged[v]))
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
