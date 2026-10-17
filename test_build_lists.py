"""Run from this folder: python3 -m unittest test_build_lists"""

import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import build_lists as b

HERE = Path(__file__).resolve().parent
TESTDATA = HERE / "testdata"


def new_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


def decode_bundle(data: bytes, public_key) -> tuple[int, dict]:
    """Independent reader for format v1 (verifies the signature)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    assert data[:4] == b"DGL1"
    built_at, count = struct.unpack(">QH", data[4:14])
    pos, sections = 14, {}
    for _ in range(count):
        id_len = data[pos]
        sid = data[pos + 1:pos + 1 + id_len].decode()
        pos += 1 + id_len
        stype, length = struct.unpack(">BI", data[pos:pos + 5])
        pos += 5
        sections[sid] = (stype, data[pos:pos + length])
        pos += length
    signed = pos
    (sig_len,) = struct.unpack(">H", data[pos:pos + 2])
    assert len(data) == pos + 2 + sig_len
    public_key.verify(data[pos + 2:], data[:signed], ec.ECDSA(hashes.SHA256()))
    return built_at, sections


def hashes_of(section: bytes) -> list[int]:
    return list(struct.unpack(f">{len(section) // 8}q", section))


class NormalizeTest(unittest.TestCase):

    def test_normalize_domain(self):
        self.assertEqual(b.normalize_domain("Example.COM."), "example.com")
        self.assertEqual(b.normalize_domain(" xn--bcher-kva.example "), "xn--bcher-kva.example")
        self.assertEqual(b.normalize_domain("_dmarc.example.com"), "_dmarc.example.com")
        for bad in ["", "com", "localhost", "localhost.localdomain", "192.168.0.1", "::1", "1.2.3.4.5",
                    "-a.example", "a-.example", "a..example", "a b.example", "exa$mple.com", "ä.example",
                    "example.com/path", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com"]:
            self.assertIsNone(b.normalize_domain(bad), bad)

    def test_parse_hosts_and_plain(self):
        text = """
        # comment
        127.0.0.1 localhost
        ::1 ip6-localhost ip6-loopback
        fe80::1%lo0 localhost
        255.255.255.255 broadcasthost
        0.0.0.0 0.0.0.0
        0.0.0.0 ads.example.com   # trailing comment
        127.0.0.1\tTRACK.example.net
        0.0.0.0 a.example b.example
        plain.example
        Plain.Example.
        10.0.0.1
        ! adblock-style comment
        """
        self.assertEqual(b.parse_domains(text.splitlines()),
                         {"ads.example.com", "track.example.net", "a.example", "b.example", "plain.example"})

    def test_allow_removes_names_and_subdomains(self):
        allow = {"google.com", "safe.example"}
        domains = {"google.com", "docs.google.com", "google.com.evil.net", "notgoogle.com", "x.safe.example", "com"}
        self.assertEqual(b.remove_allowed(domains, allow), {"google.com.evil.net", "notgoogle.com", "com"})

    def test_exact_entries_keep_subdomains_blockable(self):
        domains = {"storage.googleapis.com", "evil-bucket.storage.googleapis.com", "googleapis.com"}
        self.assertEqual(b.remove_allowed(domains, set(), {"storage.googleapis.com", "googleapis.com"}),
                         {"evil-bucket.storage.googleapis.com"})

    def test_allow_file_parses(self):
        allow, exact, essential = b.load_allow(HERE / "allow.txt")
        self.assertIn("google.com", allow)
        self.assertIn("gvt1.com", allow)  # inline comment stripped
        self.assertIn("fcm.googleapis.com", allow)
        self.assertIn("storage.googleapis.com", exact)
        self.assertIn("connectivitycheck.gstatic.com", essential)
        self.assertLessEqual(len(essential), 10)  # keep the never-block-anything set tiny
        for user_content in ["github.io", "googleusercontent.com", "amazonaws.com", "blogspot.com", "windows.net",
                             "googleapis.com", "storage.googleapis.com", "appspot.com", "cloudfront.net"]:
            self.assertNotIn(user_content, allow)

    def test_numbers(self):
        self.assertEqual(b.normalize_number("+1 (202) 555-0111"), "2025550111")
        self.assertIsNone(b.normalize_number("0000000000"))
        self.assertIsNone(b.normalize_number("2021234567"))
        self.assertIsNone(b.normalize_number(None))
        recs = [{"attributes": {"company-phone-number": n}} for n in
                ["2025550111", "202-555-0111", "3105550142", "8005550199", "8005550199", ""]]
        counts = b.count_reports(recs)
        self.assertEqual(counts, Counter({"2025550111": 2, "3105550142": 1, "8005550199": 2}))
        self.assertEqual(b.select_numbers(counts, 2, {"8005550199"}), ["2025550111"])


class HashTest(unittest.TestCase):

    def test_hash_matches_spec(self):
        digest = hashlib.sha256(b"example.com").digest()
        self.assertEqual(b.domain_hash("example.com"), int.from_bytes(digest[:8], "big", signed=True))
        self.assertEqual(b.domain_hash("Example.COM."), b.domain_hash("example.com"))
        self.assertNotEqual(b.domain_hash("example.com.."), b.domain_hash("example.com"))
        # Same vectors as core/src/test/.../ListBundleTest.kt.
        self.assertEqual(b.domain_hash("example.com"), -6667114193848649307)
        self.assertEqual(b.domain_hash("evil-phish.example"), 4206730978545985053)
        self.assertEqual(b.domain_hash(""), -2039914840885289964)

    def test_section_sorted_signed_and_deduped(self):
        names = ["a.com", "b.com", "c.com", "a.com", "d.org", "e.net"]
        values = hashes_of(b.hash_section(names))
        self.assertEqual(values, sorted(set(values)))
        self.assertEqual(len(values), 5)
        self.assertEqual(b.hash_section([]), b"")


class BundleTest(unittest.TestCase):

    def test_encode_and_verify(self):
        from cryptography.exceptions import InvalidSignature
        key = new_key()
        data = b.encode_bundle(42, [("scam", 1, b.hash_section(["evil.example"])), ("numbers", 2, b"2025550111")], key)
        built_at, sections = decode_bundle(data, key.public_key())
        self.assertEqual(built_at, 42)
        self.assertEqual(sections["scam"], (1, struct.pack(">q", b.domain_hash("evil.example"))))
        self.assertEqual(sections["numbers"], (2, b"2025550111"))
        tampered = bytearray(data)
        tampered[30] ^= 1  # inside the scam hash data
        with self.assertRaises(InvalidSignature):
            decode_bundle(bytes(tampered), key.public_key())
        with self.assertRaises(InvalidSignature):
            decode_bundle(data, new_key().public_key())

    def test_rejects_non_p256_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pem = ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(SystemExit):
            b.load_private_key(pem)


class EndToEndTest(unittest.TestCase):
    """Runs the CLI offline against testdata/."""

    def run_builder(self, *extra, sources=TESTDATA):
        from cryptography.hazmat.primitives import serialization
        key = new_key()
        with tempfile.TemporaryDirectory() as tmp:
            pem = Path(tmp) / "key.pem"
            pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
            out = Path(tmp) / "out.bin"
            notes = Path(tmp) / "notes.md"
            result = subprocess.run(
                [sys.executable, str(HERE / "build_lists.py"), "--key", str(pem), "--sources-dir", str(sources),
                 "--allow", str(TESTDATA / "allow.txt"), "--never-block", str(TESTDATA / "never_block.txt"),
                 "--min-per-source", "1", "--built-at", "1760000000", "--out", str(out), "--summary", str(notes),
                 *extra],
                capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "FTC_API_KEY": ""})
            if result.returncode != 0:
                return result, None, None
            return result, decode_bundle(out.read_bytes(), key.public_key()), notes.read_text()

    def test_builds_all_sections(self):
        result, (built_at, sections), notes = self.run_builder("--numbers-file", str(TESTDATA / "numbers.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(built_at, 1760000000)
        scam = set(hashes_of(sections["scam"][1]))
        self.assertEqual(scam, {b.domain_hash(d) for d in
                                ["evil-phish.example", "login-paypa1.example.net", "malware-drop.example.org"]})
        # Allow roots don't touch ads (cdn.safe.example stays); "!" essentials leave every list.
        ads = set(hashes_of(sections["ads"][1]))
        self.assertEqual(ads, {b.domain_hash(d) for d in
                               ["ads.tracker.example", "pixel.example.com", "metrics.example.com", "cdn.safe.example"]})
        self.assertNotIn(b.domain_hash("netcheck.example"), scam | ads)
        self.assertEqual(set(hashes_of(sections["allow"][1])), {b.domain_hash("google.com"), b.domain_hash("safe.example")})
        self.assertEqual(sections["numbers"], (2, b"2025550111\n3105550142"))
        self.assertIn("scam: 3", result.stdout)
        self.assertIn("ads: 4", result.stdout)
        self.assertIn("| numbers | 2 |", notes)

    def test_numbers_skipped_without_api_key(self):
        result, (_, sections), notes = self.run_builder()
        self.assertNotIn("numbers", sections)
        self.assertIn("not included", notes)

    def test_missing_source_fails_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Only one source present; the others would be downloaded from an unreachable host.
            (Path(tmp) / "urlhaus-hostfile.txt").write_text("")
            for name in ["phishing-domains-ACTIVE.txt", "stevenblack-hosts.txt"]:
                (Path(tmp) / name).write_text((TESTDATA / name).read_text())
            result, bundle, _ = self.run_builder("--skip-numbers", sources=Path(tmp))
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(bundle)
            self.assertIn("URLhaus", result.stderr)


if __name__ == "__main__":
    unittest.main()
