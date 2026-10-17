# DoberGuard lists

The block lists used by [DoberGuard](https://github.com/Xenocideplayer/doberguard)
Shield (scam and ad blocking for the whole phone) and by the DoberGuard spam
call and text blocker.

Every Monday a GitHub Action downloads the sources below, merges them into one
signed file and attaches it to the release tagged `latest`:

```
https://github.com/Xenocideplayer/doberguard-lists/releases/download/latest/doberguard-lists.bin
```

The apps check the signature with a public key built into them, so a file that
didn't come from this pipeline is rejected.

## Sources

| Section | Source | License | What it adds |
|---|---|---|---|
| `scam` | [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) `phishing-domains-ACTIVE.txt` | MIT | Phishing domains that are currently live |
| `scam` | [URLhaus](https://urlhaus.abuse.ch/) hostfile, by abuse.ch | CC0 | Hosts serving malware |
| `ads` | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) base `hosts` (adware + malware) | MIT; the lists it merges are credited in its README | Ad, tracking and malware hosts |
| `numbers` | [FTC Do Not Call complaints API](https://www.ftc.gov/developer/api/v0/endpoints/do-not-call-dnc-reported-calls-data-api) | US government work, public domain | Phone numbers reported at least twice in the last 7 days |
| `allow` | [`allow.txt`](allow.txt) in this repo | ours | Domains that must never be blocked as scams |

Thank you to the maintainers of these projects. Please report wrong entries to
the source list they came from; domains that should never be blocked can be
proposed for `allow.txt` here.

Notes:

- Names are lowercased and de-duplicated; comments, IP addresses, `localhost`
  entries and invalid names are dropped.
- `allow.txt` only protects against scam false positives: anything in it, or
  under a domain in it, is removed from `scam`, and the app ignores scam hits
  under those domains. It never un-blocks ads; the `ads` section keeps its
  source as is. Lines starting with `=` remove only that exact host from
  `scam` (its subdomains can still be blocked); lines starting with `!` remove
  that exact host from every section and are kept to a handful of hosts the
  phone can't work without (connectivity checks, push).
- The FTC data is consumer-reported and unverified. Numbers in
  [`never_block.txt`](never_block.txt) are never listed.
- If a domain source can't be downloaded the build fails, so a bundle missing
  a section is never published. The `numbers` section is optional: it is left
  out when `FTC_API_KEY` is not set or the FTC API fails.

## Bundle format

`doberguard-lists.bin` is format v1 from the app's
[`docs/shield-spec.md`](https://github.com/Xenocideplayer/doberguard/blob/main/docs/shield-spec.md).
In short (big-endian):

```
"DGL1" | builtAt u64 (epoch s) | sectionCount u16
  { idLen u8 | id ASCII | type u8 (1 = domain hashes, 2 = UTF-8 text) | dataLen u32 | data }
sigLen u16 | DER ECDSA P-256 / SHA-256 signature over every byte before sigLen
```

Domains are stored as hashes, not names: lowercase the name, strip one trailing
`.`, SHA-256 it, and take the first 8 bytes as a big-endian signed 64-bit
integer. Each domain section is those integers sorted ascending (as signed),
with no duplicates. `numbers` is one 10-digit US number per line, sorted.
Readers ignore sections they don't know.

## Running it yourself

Needs Python 3.9+ and `pip install cryptography`.

```sh
# A throwaway P-256 key for testing:
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out test-key.pem

python3 build_lists.py --key test-key.pem --skip-numbers --out doberguard-lists.bin
python3 -m unittest test_build_lists
```

Useful flags: `--sources-dir DIR` reads pre-downloaded sources
(`phishing-domains-ACTIVE.txt`, `urlhaus-hostfile.txt`,
`stevenblack-hosts.txt`) instead of downloading them; `--skip-numbers`;
`--days N` and `--min-reports N` for the FTC data (defaults 7 and 2);
`--summary FILE` writes release notes. Fetching a week of FTC complaints takes
a few thousand API requests, which at the free key's 1,000 requests per hour
is a few hours.

## Secrets

In this repo's **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
|---|---|
| `LISTS_SIGNING_KEY` | The list signing private key, PEM (`-----BEGIN PRIVATE KEY-----` ...). Its public key must match `BundleKeys.LISTS_PUBLIC_KEY_B64` in the app; the build log prints the public key it signed with. |
| `FTC_API_KEY` | A free key from <https://api.data.gov/signup/>. Optional: without it the bundle has no `numbers` section. |

The workflow needs `contents: write` (already set in
[`build.yml`](.github/workflows/build.yml)) to create and update the `latest`
release.
