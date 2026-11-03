# pqc-assess

Inventory the cryptography in a customer's software and say what to migrate to
post-quantum cryptography (PQC).

No single open-source scanner covers enough on its own, so pqc-assess runs
several, each where it is strongest. It merges what they find into one CycloneDX
1.6 CBOM and writes a report that gives each finding a risk level and a
recommended replacement.

| Scanner | Reads | How |
|---|---|---|
| [CBOMkit](https://github.com/cbomkit/sonar-cryptography) (PQCA) | Java, Python, Go, C# source | semantic: follows the call to the algorithm, key size and curve |
| [CryptoScan](https://github.com/csnp/cryptoscan) | any source and configuration (C/C++, JS, nginx, ...) | patterns; also certificate validation bypass and keys in code |
| [qryx](https://github.com/TAIPANBOX/qryx) | Go, Python, JS/TS, Rust source; native binaries that import a crypto library | AST and import tables |
| `pqc_assess.detectors.jar` | compiled Java: `.jar`, `.war`, `.ear`, `.class` | bytecode: the constant passed to each JCA `getInstance`, key sizes, BouncyCastle classes |
| `pqc_assess.detectors.gobinary` | Go binaries, stripped ones included | the runtime's function table and build info |
| `pqc_assess.detectors.jose` | JWT and JOSE signing in any language: `'RS256'`, `SignatureAlgorithm.ES256`, `Algorithm.RSA256(...)` | identifiers and library enums; the upstream scanners miss these |

## Use

Requires Docker and Python 3.10 or later; pqc-assess uses the standard library only.

```sh
python3 -m pqc_assess build                         # once: build/pull the pinned scanner images
python3 -m pqc_assess scan /path/to/customer -o out # scan, merge, report
```

`out/` then holds:

- `report.md`: summary by risk, what to migrate, the findings in application code with the tools that saw them, and, apart, the matches in tests, docs, translations and data, and the lines that name an algorithm only in a file extension, URL or query string
- `cbom.json`: the merged CBOM, each component carrying `pqc-assess:risk`, `pqc-assess:recommendation` and `pqc-assess:tools`
- `findings.json`: the merged findings as a list
- `raw/`: each scanner's own output and log. **This holds lines of the customer's code**, keys in it included; treat it as the customer's data.

`--tools cryptoscan,cbomkit,qryx,jar,gobin,jose` runs a subset. `merge -o out A.cbom.json B.cbom.json` merges CBOMs made elsewhere; each file's tool is its name before the first dot.

On a small machine such as a Raspberry Pi, install with `scripts/deploy.sh HOST`
from the development machine instead of running `build` there. `build` compiles
the scanners in the `golang` image, close to 1 GB with its build cache, and fills
a small SD card. A scan itself needs a few hundred MB free for the staged copy
of the target and CBOMkit's work.

## Isolation

The target and the scanners are both untrusted. The target is copied without its
symbolic links before any scanner sees it. Each scanner then runs in a container
with no network, no capabilities, the copy mounted read-only, and the host
user's uid. A scanner cannot send the customer's code anywhere, and a link such
as `innocent.py -> ~/.ssh/id_rsa` leads nowhere.

## Versions and patches

`tools.lock.json` pins each scanner: CBOMkit by image digest, qryx by module
version, and CryptoScan by commit. `patches/cryptoscan/` holds the changes
CryptoScan needs and upstream does not have yet:

1. do not follow symbolic links (it copied the target's lines into the report);
2. match `DES3`, `DES-CBC3`, `EVP_des_ede3*`, `EVP_aes_*` and `EVP_PKEY_EC`/`NID_*` curves.

Send each patch upstream. When upstream merges it, move the commit in
`tools.lock.json` forward and delete the patch. To update a scanner, change its
entry and run `build` again.

## Limits

- A Go binary names the packages linked into it. That is the application or the
  standard library: `crypto/tls` links `crypto/rsa` to verify certificates. The
  evidence lists the functions, and `GenerateKey` means the application makes keys.
- Stripped, statically linked C/C++ and Rust binaries are not covered. Detecting
  those needs constant signatures (AES S-box, SHA round constants), which is not
  built yet.
- CryptoScan keeps one finding per line and category, so RSA and EC on the same
  line of C come out as one.
- An algorithm chosen at run time (from configuration, a database or user input)
  is invisible to any static scan.

## Tests

The unit tests need neither Docker nor the network:

```sh
python3 -m unittest discover -s tests -t .
```

The scanners are checked end to end on the fixtures, which hold crypto in six
languages, nginx, a `.jar` and a stripped Go binary. Every tool must print `ok`:

```sh
python3 -m pqc_assess scan tests/fixtures -o /tmp/pqc-assess-selftest
```

Before a demo, scan the two real applications at the commits used so far and
compare the counts. A change in the counts means a change in what pqc-assess
reports; read the diff of `findings.json` before accepting it.

```sh
git clone https://github.com/WebGoat/WebGoat.git && git -C WebGoat checkout be2c186
git clone https://github.com/juice-shop/juice-shop.git && git -C juice-shop checkout 717f5ef
python3 -m pqc_assess scan WebGoat -o out-WebGoat       # 147 findings, 111 in code
python3 -m pqc_assess scan juice-shop -o out-juice-shop # 48 findings, 21 in code
```

Each takes about a minute. Keep `out-*` out of the repository: `raw/` holds the
applications' code.

## Changes

Change the code in a git clone on the development machine, never in a copy that
`deploy.sh` installed: that copy is a `git archive` with no history. Then:

```sh
python3 -m unittest discover -s tests -t .
git commit -am "..."
git push origin main
scripts/deploy.sh HOST            # update the machine that runs the demo
```

`deploy.sh` copies `HEAD`, so commit before deploying. It ends by running the
unit tests and the fixture scan on HOST.
