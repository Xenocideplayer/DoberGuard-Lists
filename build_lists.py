#!/usr/bin/env python3
"""
Build the signed DoberGuard list bundle (doberguard-lists.bin).

Sections (bundle format v1, see README.md):
  scam     Phishing.Database ACTIVE domains + URLhaus hostfile   (domain hashes)
  ads      StevenBlack/hosts base hosts file                     (domain hashes)
  adult    StevenBlack/hosts porn-only (porn extension)           (domain hashes)
  allow    allow.txt: domains that must never be blocked as scams (domain hashes)
  numbers  FTC Do Not Call complaints, optional                  (text, one number per line)

Usage:
    export LISTS_SIGNING_KEY="$(cat lists-private.pem)"   # or --key lists-private.pem
    export FTC_API_KEY=...                                  # optional; numbers skipped without it
    python3 build_lists.py --out doberguard-lists.bin

Offline testing:
    python3 build_lists.py --sources-dir DIR --skip-numbers --key test.pem
DIR may hold any of phishing-domains-ACTIVE.txt, urlhaus-hostfile.txt and
stevenblack-hosts.txt; missing ones are downloaded.

A domain source that can't be downloaded (or yields suspiciously few names)
fails the build, so a bundle is never published with a section missing.
The numbers section is optional: if the FTC fetch fails it is left out.

Needs Python 3.9+ and the `cryptography` package.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

HERE = Path(__file__).resolve().parent
USER_AGENT = "DoberGuard-lists/1.0 (+https://github.com/Xenocideplayer/doberguard-lists)"

MAGIC = b"DGL1"
TYPE_DOMAINS = 1
TYPE_TEXT = 2


class Source:
    def __init__(self, name: str, section: str, url: str, filename: str):
        self.name, self.section, self.url, self.filename = name, section, url, filename


SOURCES = [
    Source("Phishing.Database", "scam",
           "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
           "phishing-domains-ACTIVE.txt"),
    Source("URLhaus", "scam", "https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus-hostfile.txt"),
    Source("StevenBlack/hosts", "ads", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
           "stevenblack-hosts.txt"),
    # Sinfonietta and Clefspeare13 pornhosts (MIT), Tiuxo and brijrajparmar27 (CC BY 4.0), via StevenBlack.
    Source("StevenBlack/hosts porn extension", "adult",
           "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
           "stevenblack-porn-only.txt"),
]

# ---------------------------------------------------------------- domains

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_HOST_PREFIXES = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255", "fe80::1%lo0", "ff00::0",
                  "ff02::1", "ff02::2", "ff02::3"}
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
                "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
                "ip6-allhosts", "0.0.0.0"}


def normalize_domain(raw: str) -> str | None:
    """Lowercased domain, or None if it isn't a plausible public DNS name."""
    name = raw.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253 or name in _LOCAL_NAMES:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    labels = name.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():  # not a real TLD: probably a malformed IP
        return None
    return name


def parse_domains(lines: Iterable[str]) -> set[str]:
    """Hosts-file or plain one-domain-per-line text → set of normalized domains."""
    out: set[str] = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        tokens = line.split()
        if tokens[0] in _HOST_PREFIXES or _looks_like_ip(tokens[0]):
            tokens = tokens[1:]  # hosts format: "0.0.0.0 name [name ...]"
        for token in tokens:
            name = normalize_domain(token)
            if name:
                out.add(name)
    return out


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token.split("%", 1)[0])
        return True
    except ValueError:
        return False


def load_allow(path: Path) -> tuple[set[str], set[str], set[str]]:
    """allow.txt → (roots, exact, essential).

    The allow list only protects against SCAM false positives; it never
    un-blocks ads (ad blocking is the paid feature).
      name    root: it and its subdomains are removed from `scam`, and it ships
              in the bundle's `allow` section so the app suppresses scam hits too.
      =name   exact host removed from `scam` only (not shipped); its subdomains
              can still be blocked (e.g. storage.googleapis.com buckets).
      !name   exact host removed from every section, ads included. Only for the
              few hosts a phone can't work without (connectivity checks, push).
    """
    roots, exact, essential = [], [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("="):
            exact.append(line[1:])
        elif line.startswith("!"):
            essential.append(line[1:])
        else:
            roots.append(line)
    return parse_domains(roots), parse_domains(exact), parse_domains(essential)


def is_allowed(domain: str, allow: set[str]) -> bool:
    """True if domain or any parent of it is in allow."""
    labels = domain.split(".")
    return any(".".join(labels[i:]) in allow for i in range(len(labels) - 1))


def remove_allowed(domains: set[str], allow: set[str], exact: frozenset[str] | set[str] = frozenset()) -> set[str]:
    return {d for d in domains if d not in exact and not is_allowed(d, allow)}


def domain_hash(domain: str) -> int:
    """Spec: lowercase, strip one trailing '.', UTF-8, SHA-256, first 8 bytes big-endian signed."""
    name = domain.lower()
    if name.endswith("."):
        name = name[:-1]
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "big", signed=True)


def hash_section(domains: Iterable[str]) -> bytes:
    hashes = sorted({domain_hash(d) for d in domains})
    return struct.pack(f">{len(hashes)}q", *hashes)

# ---------------------------------------------------------------- bundle


def encode_bundle(built_at: int, sections: list[tuple[str, int, bytes]], private_key) -> bytes:
    """Bundle format v1: magic, builtAt, sections, then a DER ECDSA-P256/SHA-256 signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    body = bytearray(MAGIC)
    body += struct.pack(">QH", built_at, len(sections))
    for section_id, section_type, data in sections:
        ident = section_id.encode("ascii")
        body += struct.pack(">B", len(ident)) + ident + struct.pack(">BI", section_type, len(data)) + data
    signature = private_key.sign(bytes(body), ec.ECDSA(hashes.SHA256()))
    return bytes(body) + struct.pack(">H", len(signature)) + signature


def load_private_key(pem: bytes):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise SystemExit("signing key must be an EC P-256 (secp256r1) private key")
    return key


def public_key_b64(private_key) -> str:
    import base64
    from cryptography.hazmat.primitives import serialization

    der = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()

# ---------------------------------------------------------------- downloads


def download(url: str, attempts: int = 3) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            last = e
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"download failed: {url}: {last}")


def read_source(source: Source, sources_dir: Path | None) -> str:
    if sources_dir and (sources_dir / source.filename).exists():
        print(f"  {source.name}: reading {sources_dir / source.filename}", file=sys.stderr)
        return (sources_dir / source.filename).read_text(encoding="utf-8", errors="replace")
    print(f"  {source.name}: downloading {source.url}", file=sys.stderr)
    return download(source.url)

# ---------------------------------------------------------------- FTC numbers
# Same logic as tools/build_blocklist.py in the app repo, copied so this
# directory is self-contained.

FTC_API = "https://api.ftc.gov/v0/dnc-complaints"
FTC_PAGE_SIZE = 50  # API maximum


def normalize_number(raw: str | None) -> str | None:
    """Match the app's core/PhoneNumbers.kt: digits only, US numbers as 10 digits."""
    if not raw:
        return None
    digits = "".join(c for c in raw if c.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in "23456789" or digits[3] not in "23456789":
        return None
    return digits


def count_reports(records: Iterable[dict]) -> Counter:
    counts: Counter = Counter()
    for record in records:
        number = normalize_number(record.get("attributes", {}).get("company-phone-number"))
        if number:
            counts[number] += 1
    return counts


def select_numbers(counts: Counter, min_reports: int, never: set[str]) -> list[str]:
    return sorted(n for n, c in counts.items() if c >= min_reports and n not in never)


def load_never_block(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        n = normalize_number(line.split("#", 1)[0].strip())
        if n:
            out.add(n)
    return out


def fetch_page(api_key: str, day: dt.date, offset: int, max_retries: int = 6) -> dict:
    params = {"created_date": day.isoformat(), "items_per_page": FTC_PAGE_SIZE, "offset": offset}
    url = f"{FTC_API}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"X-Api-Key": api_key, "User-Agent": USER_AGENT})
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code == 429:  # free api.data.gov keys allow 1,000 requests per hour
                wait = 60 * (attempt + 1)
                print(f"  rate limited, waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            if 500 <= e.code < 600:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"giving up on {day} offset {offset}")


def complaints_for_day(api_key: str, day: dt.date) -> Iterator[dict]:
    offset = 0
    while True:
        page = fetch_page(api_key, day, offset)
        records = page.get("data") or []
        yield from records
        total = int(page.get("meta", {}).get("records-total", 0) or 0)
        offset += len(records)
        if not records or offset >= total:
            break


def fetch_numbers(api_key: str, days: int, min_reports: int, never: set[str]) -> list[str]:
    today = dt.date.today()
    counts: Counter = Counter()
    for back in range(1, days + 1):
        day = today - dt.timedelta(days=back)
        day_counts = count_reports(complaints_for_day(api_key, day))
        print(f"  {day}: {sum(day_counts.values())} complaints, {len(day_counts)} numbers", file=sys.stderr)
        counts.update(day_counts)
    return select_numbers(counts, min_reports, never)

# ---------------------------------------------------------------- main


def build(args) -> int:
    pem = Path(args.key).read_bytes() if args.key else os.environ.get("LISTS_SIGNING_KEY", "").encode()
    if not pem.strip():
        print("Set LISTS_SIGNING_KEY (PEM) or pass --key", file=sys.stderr)
        return 2
    key = load_private_key(pem)
    print(f"Signing with public key {public_key_b64(key)}", file=sys.stderr)

    allow, exact, essential = load_allow(args.allow)
    domains: dict[str, set[str]] = {"scam": set(), "ads": set(), "adult": set()}
    per_source: list[tuple[str, int]] = []
    print("Domain sources:", file=sys.stderr)
    for source in SOURCES:
        try:
            names = parse_domains(read_source(source, args.sources_dir).splitlines())
        except Exception as e:  # noqa: BLE001 - any failure here must stop the build
            print(f"ERROR: {source.name}: {e}", file=sys.stderr)
            return 1
        if len(names) < args.min_per_source:
            print(f"ERROR: {source.name} gave only {len(names)} domains (< {args.min_per_source})", file=sys.stderr)
            return 1
        per_source.append((source.name, len(names)))
        domains[source.section] |= names

    scam = remove_allowed(domains["scam"], allow, exact | essential)
    ads = domains["ads"] - essential  # allow.txt roots never un-block ads
    adult = domains["adult"] - essential  # nor adult sites
    sections = [
        ("scam", TYPE_DOMAINS, hash_section(scam)),
        ("ads", TYPE_DOMAINS, hash_section(ads)),
        ("allow", TYPE_DOMAINS, hash_section(allow)),
        ("adult", TYPE_DOMAINS, hash_section(adult)),
    ]
    counts = {"scam": len(sections[0][2]) // 8, "ads": len(sections[1][2]) // 8, "allow": len(allow),
              "adult": len(sections[3][2]) // 8}
    removed = len(domains["scam"]) - len(scam) + len(domains["ads"]) - len(ads)

    api_key = os.environ.get("FTC_API_KEY", "").strip()
    if args.numbers_file:
        never = load_never_block(args.never_block)
        numbers = sorted({n for n in map(normalize_number, args.numbers_file.read_text().split()) if n} - never)
        print(f"Numbers: read {len(numbers)} from {args.numbers_file}", file=sys.stderr)
        sections.append(("numbers", TYPE_TEXT, "\n".join(numbers).encode("ascii")))
        counts["numbers"] = len(numbers)
    elif args.skip_numbers or not api_key:
        print("Numbers: skipped" + ("" if args.skip_numbers else " (FTC_API_KEY not set)"), file=sys.stderr)
    else:
        print(f"Numbers: FTC complaints, last {args.days} days, >= {args.min_reports} reports", file=sys.stderr)
        try:
            numbers = fetch_numbers(api_key, args.days, args.min_reports, load_never_block(args.never_block))
            sections.append(("numbers", TYPE_TEXT, "\n".join(numbers).encode("ascii")))
            counts["numbers"] = len(numbers)
        except Exception as e:  # noqa: BLE001 - numbers are optional
            print(f"WARNING: numbers left out: {e}", file=sys.stderr)

    built_at = args.built_at if args.built_at is not None else int(time.time())
    bundle = encode_bundle(built_at, sections, key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(bundle)

    stamp = dt.datetime.fromtimestamp(built_at, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for name, n in per_source:
        print(f"  source {name}: {n} domains", file=sys.stderr)
    print(f"  removed by allow list: {removed} (scam {len(domains['scam']) - len(scam)}, "
          f"ads {len(domains['ads']) - len(ads)})", file=sys.stderr)
    for section, n in counts.items():
        print(f"{section}: {n}")
    print(f"Wrote {args.out} ({len(bundle)} bytes), built {stamp}")

    if args.summary:
        lines = [f"DoberGuard lists built {stamp} (builtAt {built_at}).", "",
                 "| Section | Entries |", "|---|---|"]
        lines += [f"| {s} | {n:,} |" for s, n in counts.items()]
        if "numbers" not in counts:
            lines.append("| numbers | not included |")
        lines += ["", "Sources: " + ", ".join(f"{name} ({n:,})" for name, n in per_source) + ".",
                  f"Bundle size: {len(bundle):,} bytes."]
        args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("doberguard-lists.bin"))
    parser.add_argument("--key", help="PEM private key file (default: env LISTS_SIGNING_KEY)")
    parser.add_argument("--sources-dir", type=Path, help="read pre-downloaded sources from here")
    parser.add_argument("--allow", type=Path, default=HERE / "allow.txt")
    parser.add_argument("--skip-numbers", action="store_true", help="leave out the FTC numbers section")
    parser.add_argument("--numbers-file", type=Path,
                        help="take numbers from this file (whitespace-separated) instead of the FTC API")
    parser.add_argument("--days", type=int, default=7, help="days of FTC complaints to use (default 7)")
    parser.add_argument("--min-reports", type=int, default=2, help="complaints before a number is listed (default 2)")
    parser.add_argument("--never-block", type=Path, default=HERE / "never_block.txt",
                        help="numbers that must never be listed")
    parser.add_argument("--min-per-source", type=int, default=50,
                        help="fail if a domain source yields fewer names than this (default 50)")
    parser.add_argument("--summary", type=Path, help="also write Markdown release notes here")
    parser.add_argument("--built-at", type=int, help=argparse.SUPPRESS)  # fixed timestamp, for test fixtures
    return build(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
