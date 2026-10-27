# jwt-check

A CLI validator for JSON Web Tokens, written against the RFCs. It decodes
compact JWS tokens and checks what the specs actually say: `alg: none`
means no integrity protection, HMAC keys have a minimum size, expired and
not-yet-valid tokens must not be accepted, and `exp`/`nbf`/`iat` must be
NumericDates. It also verifies HS256/384/512 signatures against a supplied
secret and matches issuer/audience.

Pure Python standard library. No network, no third-party JWT library.

## The problem

Tokens get pasted into debugging sessions and test fixtures with the
assumption that "the library will catch anything wrong." But small
mistakes - a missing `exp`, a secret shorter than the HMAC minimum, a
leftover `alg: none` test token, a token checked against the wrong
issuer - slide through. jwt-check is the offline second opinion: paste a
token, get findings tied to the RFC sections they come from.

## Usage

```bash
python3 jwt_check.py eyJhbGciOi...
python3 jwt_check.py @token.txt --secret "$JWT_SECRET"
python3 jwt_check.py TOKEN --issuer https://auth.example.com --audience api
python3 jwt_check.py TOKEN --now 1800000000 --format json
```

Pass several tokens to check them in one run (labeled `token 1`,
`token 2`, ...). `@file` reads a token from a file.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean (warnings only when `--fail-on-warning` is off) |
| 1 | Findings present (errors, or warnings with `--fail-on-warning`) |
| 2 | Input problem: malformed token, unreadable file |

Example output:

```
token 1 [error] alg-none: alg is "none": an Unsecured JWS provides no integrity protection (RFC 7518 sec 3.6).
token 1 [warning] missing-exp: no exp claim: the token never expires (RFC 7519 sec 4.1.4 makes exp OPTIONAL, so this is a review finding, not a violation).
jwt-check: 1 error(s), 1 warning(s)
```

## Rules

| Rule | Severity | Trigger | Grounding |
|---|---|---|---|
| `alg-none` | error | header `alg` is `none` | RFC 7518 sec 3.6: an Unsecured JWS "does not provide integrity protection" |
| `unsupported-alg` | error | `alg` is not none/HS256/HS384/HS512 | jwt-check only verifies HMAC signatures; asymmetric algs need key material it does not handle |
| `sig-verify-failed` | error | HMAC does not match with `--secret` | RFC 7518 sec 3.1/3.2 HMAC construction |
| `weak-secret` | warning | `--secret` shorter than the hash output | RFC 7518 sec 3.2: a key "of the same size as the hash output (for instance, 256 bits for HS256) or larger MUST be used" |
| `missing-exp` | warning | no `exp` claim | RFC 7519 sec 4.1.4 makes `exp` OPTIONAL - so this is a review finding, not a violation; an unexpiring token is usually unintended |
| `expired` | warning | `exp` is in the past (beyond `--leeway`) | RFC 7519 sec 4.1.4: the token MUST NOT be accepted on or after `exp` |
| `not-yet-valid` | warning | `nbf` is in the future (beyond `--leeway`) | RFC 7519 sec 4.1.5: the token MUST NOT be accepted before `nbf` |
| `iat-in-future` | warning | `iat` is in the future (beyond `--leeway`) | heuristic clock-skew check |
| `issuer-mismatch` | error | `--issuer` given and `iss` differs | RFC 7519 sec 4.1.1 |
| `audience-mismatch` | error | `--audience` given and not in `aud` (string or array) | RFC 7519 sec 4.1.3 |

`exp`/`nbf`/`iat` that are not numbers are rejected as malformed (exit 2):
RFC 7519 requires a NumericDate for all three.

## Options

```
--secret SECRET      verify the HMAC signature and check key length
--issuer ISS         require this iss value
--audience AUD       require this aud value
--now UNIX           current time as a Unix timestamp (testing/replay)
--leeway SECONDS     clock-skew leeway (default: 60; RFC 7519 allows a few minutes)
--ignore RULE        suppress a rule by name (repeatable)
--fail-on-warning    exit 1 when only warnings are present
--format text|json   output format (default: text)
```

## Caveats

- Verification covers HMAC algs only. RS/ES/PS tokens decode and get
  claim checks, but their signatures cannot be verified here and
  `unsupported-alg` says so - it does not mean the token is invalid.
- Without `--secret`, no signature check happens at all: findings are
  about structure and claims, not authenticity.
- `missing-exp` and `iat-in-future` are review findings: the RFC makes
  `exp` optional and does not require `iat` to be in the past.

## Sources

- RFC 7519, JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 7518, JSON Web Algorithms (JWA), sec 3.2 (HMAC keys) and 3.6
  ("none"): https://www.rfc-editor.org/rfc/rfc7518

## Development

57 tests, all with fabricated tokens signed via stdlib `hmac`, a fixed
`--now` clock, and no network:

```bash
python3 -m unittest -v
```

CI runs the suite on Ubuntu and Windows with Python 3.9 and 3.13.

## License

MIT - see LICENSE.
