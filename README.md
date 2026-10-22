# lowkey-check

Check public keys for **small EC private scalars, shared RSA factors, ROCA
fingerprints, and RSA primes close enough for bounded Fermat factorization**.
Accepts public keys, X.509 certificates, CSV exports, and live TLS certificate
chains. EC support includes **P-192, P-224, P-256, P-384, P-521, secp256k1,
and all 14 RFC 5639 Brainpool curves**. Optional Certificate Transparency (CT)
lookups enrich weak-key findings with public certificate details from
[ctlogs.dev](https://ctlogs.dev/).

**An OK result is not a security guarantee.** It means only that these checks
found nothing within the selected input corpus and search budgets. This is not
a comprehensive weak-key detector, certificate validator, or practical attack
on properly generated keys.
Only scan systems and data you are authorized to assess.

## Install

### Prebuilt binaries

When available, download the matching OS/architecture ZIP from
[GitHub Releases](https://github.com/scovetta/lowkey/releases), extract it, and
run `lowkey-check.exe --help` on Windows or `./lowkey-check --help` on Linux/macOS
(run `chmod +x lowkey-check` first if necessary). Rust and a separate
OpenSSL installation are not required to run these binaries.

### Build from source

Install a current stable [Rust toolchain](https://rustup.rs/) with Cargo
(Rust 2024 edition support is required). **OpenSSL is not required.**
EC and RSA arithmetic, SHA-256, and certificate parsing use Rust implementations.
TLS still uses rustls with `ring`, which includes native C/assembly, so the
standard platform build tools remain necessary:

| Platform | Build prerequisites |
|----------|---------------------|
| Windows (MSVC) | Visual Studio C++ Build Tools and Windows SDK |
| Linux | C compiler and archiver, such as the `build-essential` package on Debian/Ubuntu |
| macOS | Xcode Command Line Tools |

Then run from the repository:

```powershell
cargo install --path . --locked
lowkey-check --help
```

Alternatively, `cargo build --release --locked` creates
`target\release\lowkey-check.exe` on Windows (`target/release/lowkey-check` on
Linux/macOS). Release builds are strongly recommended for scanning.

## Quick start

```powershell
# Check EC scalars 0-32767 and run the default RSA checks automatically.
lowkey-check .\cert.pem

# Check a specific inclusive range using four workers.
lowkey-check --range 1-1000000 --threads 4 .\public-key.der

# Read PEM from standard input ("-" or no path).
Get-Content -Raw .\public-key.pem | lowkey-check -

# Check every certificate presented by a TLS server.
lowkey-check https://example.com
lowkey-check --leaf-only tls://example.com:443

# Check a CSV export with an explicit column.
lowkey-check --column "X.509 Certificate (PEM)" .\certificates.csv

# Try more Fermat candidates per RSA modulus, or disable Fermat with 0.
lowkey-check --fermat-steps 10000 .\rsa-cert.pem

# Load public CT details only for certificates with findings.
lowkey-check --ct-details .\cert.pem

# Check only selected CCADB years (inclusive).
lowkey-check --check-ccadb --year 2005-2010
lowkey-check --check-ccadb --year 2020
lowkey-check --check-ccadb --year -2010
lowkey-check --check-ccadb --year 2015-
```

## Supported curves

| Family | Named curves |
|--------|--------------|
| NIST | P-192 (`secp192r1` / `prime192v1`), P-224 (`secp224r1`), P-256 (`secp256r1` / `prime256v1`), P-384 (`secp384r1`), P-521 (`secp521r1`) |
| SECG | `secp256k1` |
| Brainpool (RFC 5639) | `brainpoolP160r1`, `brainpoolP160t1`, `brainpoolP192r1`, `brainpoolP192t1`, `brainpoolP224r1`, `brainpoolP224t1`, `brainpoolP256r1`, `brainpoolP256t1`, `brainpoolP320r1`, `brainpoolP320t1`, `brainpoolP384r1`, `brainpoolP384t1`, `brainpoolP512r1`, `brainpoolP512t1` |

Both Brainpool's regular (`r1`) and twisted (`t1`) variants are supported,
including compressed points. Legacy curves are supported for inspection, not
recommended for new keys: in particular, 160- and 192-bit curves have insufficient
strength for modern applications even when the scalar is not small. All NIST
and SECG curves use RustCrypto implementations.

Brainpool uses this project's Rust implementation of the published
[RFC 5639](https://www.rfc-editor.org/rfc/rfc5639) parameters, backed by
`crypto-bigint` modular arithmetic. It validates SEC1 points and uses projective
coordinates for repeated point addition. This variable-time implementation is
private to key inspection, has not been independently audited, and is **not a
signing, key-generation, or general-purpose secret-key arithmetic API**.

## RSA checks

RSA keys using `rsaEncryption`, RSASSA-PSS, or RSAES-OAEP SubjectPublicKeyInfo
algorithm identifiers are checked automatically. RSA checks do not use
`--range` or `--threads`; those options control EC scanning.

| Check | What a finding means | Limit |
|-------|----------------------|-------|
| Shared-factor batch GCD | A nontrivial factor is recovered from relationships between distinct RSA moduli | Only compares keys in the current input corpus, not an external key database |
| ROCA fingerprint | The modulus matches the structured-prime generation fingerprint associated with CVE-2017-15361 | A fingerprint match is **not factor recovery** or proof of a particular device's provenance |
| Bounded Fermat | A nontrivial factor is recovered because the factors are exceptionally close, or the modulus is a perfect square | At most **1,000 candidate values per distinct modulus** by default |

Batch GCD uses balanced product and remainder trees, not all-pairs comparison.
It deduplicates numeric moduli: ordinary certificate/key reuse is **not itself
a vulnerability**. When a modulus shares different factors with different
peers, the checker descends the product tree to isolate a proper factor rather
than mistaking a GCD equal to the whole modulus for a recovered factor.
Affected duplicate rows are still reported individually.

The comparison corpus is all RSA keys in one CSV, the presented TLS chain
(or just its leaf with `--leaf-only`), or **all successfully downloaded reports
across the selected CCADB years**. A standalone key has no other modulus to
compare against. Inputs and parsed keys are retained in memory for batch
analysis; larger corpora and product trees require more memory. Cross-year
CCADB results are printed after the selected reports have been downloaded.

The ROCA detector checks joint membership in the subgroup generated by 65537
modulo the product of primes through 167, including compatible discrete-log
congruences. This follows the modern
[CROCS-MUNI detector](https://github.com/crocs-muni/roca), avoiding the looser
original per-prime-only fingerprint. Matches print `SUSPECT`, not a recovered
private key. False positives remain possible; investigate before concluding
that the key was generated by affected hardware. Actual ROCA factorization is
not attempted.

Fermat starts at `ceil(sqrt(N))` and tests consecutive candidate values of
`a` for a square `a^2 - N`. A success verifies the resulting factors multiply
back to `N`. Set `--fermat-steps N` to change the candidate budget, or
`--fermat-steps 0` to disable Fermat, including its perfect-square check.
This is a work-count limit, **not a wall-clock deadline**; larger keys and
budgets cost more. Moduli already factored by batch GCD skip Fermat, and repeated
moduli reuse their RSA assessment. Normally generated RSA primes have similar
bit lengths; that alone does not make them vulnerable to Fermat.

Confirmed factor recoveries print `VULNERABLE` and disclose the factor and
cofactor, not a reconstructed RSA private key. Both those findings and `SUSPECT`
ROCA matches produce exit code 1 unless an error takes precedence. These checks
do not implement Wiener's small-private-exponent attack, signature nonce-reuse
analysis, or general RSA factorization.

## Live TLS inputs

URL inputs perform a TLS handshake, not an HTTP request. The URL path, query,
and fragment are ignored. Both schemes default to port 443 and support DNS
names, IPv4, and bracketed IPv6 addresses. Services requiring STARTTLS are not
supported. TLS negotiation is limited to rustls's supported protocols and
signature schemes; use a certificate file if a legacy or Brainpool-only server
cannot negotiate a compatible handshake.

**Live TLS certificates and handshake signatures are deliberately not
validated.** Expired, self-signed, or untrusted certificates can be inspected,
but an active intermediary can substitute the key being checked. No application
data or credentials are sent. The presented chain is checked leaf first; missing
intermediates and roots are not fetched. Connections and socket I/O have
10-second timeouts, not a single overall deadline; DNS resolution may take longer.

## Options

```text
lowkey-check [OPTIONS] [PATH|URL]

  -r, --range <MIN-MAX|MAX>  Inclusive EC scalar range (default: 0-32767)
      --fermat-steps <N>   RSA Fermat candidates (default: 1000; 0 disables)
  -t, --threads <N>         Positive EC worker count (default: available CPUs)
      --leaf-only          Check only the leaf certificate for URL inputs
      --column <HEADER>    Select the CSV key column, case-insensitively
  -q, --quiet              Hide OK/SKIP; findings and errors remain visible
      --check-ccadb        Download and scan CCADB reports from 1999 onward
      --year <YEARS>       CCADB: YEAR, MIN-MAX, -MAX, or MIN-
      --ct-details         Load ctlogs.dev details for weak-key findings
  -h, --help               Show help
  -V, --version            Show version
```

Range endpoints are unsigned decimal 64-bit integers. A lone maximum means
`0-MAX`; scalar zero is always excluded because it is not a valid private key.
The search uses repeated point addition across workers, so time grows linearly
with the range for **each input**. Very large ranges can take impractically long.

## Input formats

Files and standard input accept a single DER or PEM SubjectPublicKeyInfo
(`PUBLIC KEY`) or X.509 certificate (`CERTIFICATE`). EC keys must use named-curve
parameters and a valid SEC1 point. Private-key files, OpenSSH public keys, and
multi-certificate PEM bundles are not supported; split bundles into individual
files or use a CSV table. Bare RSA keys must use SubjectPublicKeyInfo
(`PUBLIC KEY`), not standalone PKCS#1 (`RSA PUBLIC KEY`) encoding. RSA moduli
and exponents must be positive, odd integers with `3 <= exponent < modulus`
and `modulus > 3`; malformed supported keys are errors.
Compressed and uncompressed EC points are supported.
PEM Base64 bodies may use nonstandard line widths or ASCII whitespace (as in
some CCADB exports); boundaries, Base64 content, and DER structure are still
validated.

Legacy ASN.1 certificate validity dates with timezone offsets or omitted seconds
are accepted for key inspection even though RFC 5280 requires UTC (`Z`) and
seconds. A pure-Rust inspection parser handles these cases while retaining
structural and public-key checks. The original certificate bytes are preserved
for CT fingerprints; this does not validate certificate trust.

Files with a `.csv` extension (case-insensitive) are parsed as CSV rather than
raw key data. The key column contains a PEM public key or certificate; standard
CSV quoting is required for multiline PEM values. Header matching ignores case
and surrounding whitespace. Auto-detection prefers a header containing
`public key`, then one containing `pem`, then a header exactly equal to
`certificate`. Use `--column` for other names or ambiguous tables. Empty key
cells are ignored; missing fields, malformed rows, and tables with no keys
produce errors. CSV on standard input is not supported.

`--check-ccadb` downloads the CCADB "All Certificate PEMs" CSV reports from
`ccadb.my.salesforce-sites.com` for each year from 1999 through the current UTC
year by default. Use `--year` to select a single year (`2020`), an inclusive
range (`2005-2010`), or a partial range (`-2010` means 1999 through 2010;
`2015-` means 2015 through the current UTC year). Years outside 1999 through the
current UTC year and reversed ranges are rejected before any downloads.
`--year` requires `--check-ccadb`, which cannot be combined with a path or URL.
This mode requires internet
access and can take a long time. Duplicate certificates remain separate output
rows, but RSA mathematics is cached by numeric modulus. A failed annual
download is reported and causes exit code 2 after the remaining years and
successfully downloaded inputs have been processed.

## Certificate Transparency details

`--ct-details` queries [ctlogs.dev's API](https://api.ctlogs.dev/) **only after
a weak-key finding is produced**, including ROCA fingerprint matches. Without
this flag, scans never perform CT lookups.
This is enrichment of an existing finding, not a scan of the entire CT corpus.

For certificate inputs (PEM/DER files, CSV cells, CCADB reports, and live TLS),
the CLI looks up the **SHA-256 fingerprint of the certificate DER** using
`/v1/cert/{fingerprint}`. This works anonymously and prints the indexed subject,
issuer, DNS SANs, serial number, validity, and CT log sightings when provided,
with a link to the public certificate record. A missing record is reported as
zero indexed certificates; it does not invalidate the weak-key finding.

Bare public keys do not have a certificate fingerprint. They use
`/v1/spki/{hash}` to find certificates sharing the exact SHA-256 SPKI fingerprint.
**ctlogs.dev requires a Pro API key for SPKI searches.** Set `CTLOGS_API_KEY` in
the environment through your secret-management workflow, then run:

```powershell
lowkey-check --ct-details .\public-key.pem
```

The key is sent in an Authorization header, never in a URL or printed output.
If set, it also authenticates certificate lookups. The CLI does not create an
account, purchase a plan, or bypass the service's access restrictions. Check the
provider's current [plans, quotas, and terms](https://api.ctlogs.dev/) before
using the feature, especially for commercial use. Anonymous requests are
currently limited to 100 per hour, one at a time.

SPKI searches print the returned issuer, matching name, serial, validity, and
record links. They follow up to 10 pages; repeated certificate IDs are
deduplicated. Provider truncation or additional pages beyond that limit produce
an explicit **results incomplete** notice. Exact certificate lookups do not
enumerate other certificates reusing the same key. SPKI matching is based on the
encoded key, so compressed and uncompressed encodings can have different hashes.

**Privacy:** opting in sends certificate or public-key fingerprints to
`api.ctlogs.dev`, which can identify the certificate/key being inspected. No
private scalar, recovered RSA factor, raw key, or certificate body is uploaded. Requests are sequential,
have a 30-second timeout and an 8 MiB response limit each, and do not follow
redirects. Results and failures are cached within each input batch. The CLI does
not automatically retry rate limits or outages.

CT details are third-party index metadata, **not verified inclusion proofs,
revocation checks, or proof of current deployment**. Index coverage, retention,
and plan limits can omit certificates. Lookup/authentication/rate-limit errors
remain visible even with `--quiet` and result in exit code 2; the original
`VULNERABLE` or `SUSPECT` result is printed first and is never downgraded.

## Results and exit codes

```text
VULNERABLE: public key: P-256 (secp256r1) private key is 7 (0x7)
VULNERABLE: public key: RSA factor recovered by bounded Fermat; factor = 101 (0x65), cofactor = 151 (0x97)
SUSPECT: public key: RSA ROCA fingerprint match (fingerprint alone does not recover factors or the private key)
OK: public key: P-256 (secp256r1) private key not in range 0-32767 (4 threads)
OK: public key: RSA (27 bits): no proper factor recovered by batch GCD; no ROCA fingerprint; Fermat: no factor within 1000 candidates
SKIP: unsupported public key algorithm OID 1.3.101.112
```

CSV and TLS results include a row or chain-index prefix (TLS index 0 is the
leaf). Unsupported algorithms and named curves are reported as `SKIP`, not
tested. Invalid encodings and invalid supported-curve points are errors, not
skips. Invalid RSA key encodings or parameters are also errors. A batch
continues checking its remaining inputs but ultimately fails.
Results go to stdout; errors and CCADB progress go to stderr.

| Exit code | Meaning |
|-----------|---------|
| `0` | No finding within the corpus and budgets; may include skipped inputs |
| `1` | At least one EC scalar recovery, RSA factor recovery, or ROCA fingerprint match, with no errors |
| `2` | Invalid arguments, input, download, connection, CT lookup, or output error |

Errors take precedence over findings in the exit status. Inspect `VULNERABLE`
and `SUSPECT` output even when the process exits with code 2. Findings expose
private scalars and RSA factors: protect scan output and replace confirmed
affected keys and certificates promptly.

## Development

```powershell
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

The checked-in `tests/fixtures/ec-vectors.json` contains independent OpenSSL
reference points for all 20 curves, including compressed/uncompressed encodings
and boundary scalars. OpenSSL is not used to regenerate expectations during
tests and is not a development dependency. Brainpool tests also check published
parameters, group-order identities, invalid points, and range partitioning.
RSA tests cover published ROCA positive/negative public moduli, an original
detector false positive, exact Fermat budget boundaries, and shared-factor
results against a pairwise-GCD oracle. Offline CCADB tests exercise cross-year
factor reuse and partial-download failures.
For a manual release-mode throughput measurement:

```powershell
cargo test --locked --release --bin lowkey-check brainpool_search_throughput -- --ignored --nocapture
```

## CI and releases

[CI](https://github.com/scovetta/lowkey/actions/workflows/ci.yml) runs on pushes
to `main`, pull requests, and manual dispatches. It checks formatting and Clippy
and runs unit/CLI integration tests and release builds on Linux, Windows, and
macOS. The offline tests do not require CT credentials or contact public CT
services. Hosted runners provide the standard platform build tools.
Rust build artifacts are cached between runs.

Successful build jobs upload 14-day platform packages named
`lowkey-check-<OS>-<ARCH>`, containing the executable, README, and license.

### Preparing a release

Use [`scripts/release.ps1`](scripts/release.ps1) with **PowerShell 7 or newer**,
Git, and Cargo with rustfmt and Clippy installed. First commit all changes,
including the release script, and switch to `main`. The script uses `origin`
and requires local `main` to contain the current remote `main`.

```powershell
# Validate the current checkout and preview a release; no version or Git changes.
pwsh -File .\scripts\release.ps1 -Version 0.2.0

# Update the version, validate, commit, tag, and push after confirmation.
.\scripts\release.ps1 -Version 0.2.0 -Publish

# Prerelease example.
.\scripts\release.ps1 -Version 0.2.0-rc.1 -Publish
```

Use `MAJOR.MINOR.PATCH`, optionally with a prerelease suffix, without a `v`
prefix or build metadata. The version cannot be lower than the current version.
A different version updates `Cargo.toml` and the workspace version in
`Cargo.lock` without upgrading dependencies, then creates a
`chore: release v<VERSION>` commit. An equal version supports the initial
release of an already-committed package version without an extra commit.

Both modes run formatting, strict Clippy, release-mode tests, and a release
build. Preview mode checks the **current** version, not an edited version.
`-Publish` checks the **updated** version, creates an annotated
`v<VERSION>` tag, and atomically pushes `main` and the tag. It never force-pushes
or replaces existing local/remote tags. `-Publish -WhatIf` also previews without
changing versions or Git refs; `-Publish -Confirm:$false` suppresses the
confirmation for deliberate automation.

Failed checks stop before the release commit/tag, leaving version edits visible
for inspection. A failed push retains the local release commit and tag; inspect
the cause before retrying the atomic push manually. No automatic reset or tag
deletion is performed. Branch protections and push permissions still apply.

Alternatively, update and commit the package version and lockfile manually,
then push a tag exactly matching `v<VERSION>` from `Cargo.toml` (for example,
`v0.1.0`).
The [release workflow](.github/workflows/release.yml) verifies the version and
reuses the full CI workflow before publishing the three platform ZIPs and
`SHA256SUMS` to GitHub Releases. Tags containing a prerelease suffix create a
prerelease. Only the publishing job has repository write permission.
The script triggers this workflow; it does not wait for completion or publish
packages locally. Check the workflow result for successful asset publication.

Release binaries are unsigned and built for the hosted runners' native OS and
architecture, not every possible target. On Linux/macOS, run
`chmod +x lowkey-check` after extracting the ZIP if necessary. The workflow does
not publish to crates.io.

## License

[MIT](LICENSE).
