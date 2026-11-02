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

## Use

Requires Docker and Python 3.10 or later; pqc-assess uses the standard library only.

```sh
python3 -m pqc_assess build                         # once: build/pull the pinned scanner images
python3 -m pqc_assess scan /path/to/customer -o out # scan, merge, report
```

`out/` then holds:

- `report.md`: summary by risk, what to migrate, every finding with the tools that saw it
- `cbom.json`: the merged CBOM, each component carrying `pqc-assess:risk`, `pqc-assess:recommendation` and `pqc-assess:tools`
- `findings.json`: the merged findings as a list
- `raw/`: each scanner's own output and log. **This holds lines of the customer's code**, keys in it included; treat it as the customer's data.

`--tools cryptoscan,cbomkit,qryx,jar,gobin` runs a subset. `merge -o out A.cbom.json B.cbom.json` merges CBOMs made elsewhere; each file's tool is its name before the first dot.

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

```sh
python3 -m unittest discover -s tests -t .
```
