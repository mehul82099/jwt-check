#!/usr/bin/env python3
"""jwt-check - a CLI validator for JSON Web Tokens.

Decodes compact JWS tokens and checks them against the RFCs: alg "none"
(Unsecured JWS), HMAC signature verification and key length (HS256/384/
512), expiration/not-before/issued-at times, and issuer/audience matching.
Pure standard library. No network, no third-party JWT library.

Sources:
- RFC 7519 (JSON Web Token): https://www.rfc-editor.org/rfc/rfc7519
- RFC 7518 (JSON Web Algorithms), sec 3.2 HMAC keys, sec 3.6 "none":
  https://www.rfc-editor.org/rfc/rfc7518
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time

HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
# RFC 7518 sec 3.2: an HMAC key MUST be at least as large as the hash
# output.
MIN_KEY_BYTES = {"HS256": 32, "HS384": 48, "HS512": 64}


class TokenError(Exception):
    """Malformed or undecodable token input (exit 2)."""


class Finding:
    def __init__(self, token, rule, severity, message):
        self.token = token
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.message = message

    def as_dict(self):
        return {
            "token": self.token,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def b64url_decode(segment):
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (binascii.Error, ValueError) as exc:
        raise TokenError("invalid base64url segment: %s" % exc)


def decode_token(raw):
    """Decode a compact JWS. Returns (signing_input, header, payload,
    signature_bytes). Raises TokenError for malformed input."""
    parts = raw.strip().split(".")
    if len(parts) != 3:
        raise TokenError(
            "expected 3 dot-separated segments, got %d" % len(parts))
    head_b, pay_b, sig = parts[0], parts[1], b64url_decode(parts[2])
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except ValueError as exc:
        raise TokenError("segment is not valid JSON: %s" % exc)
    if not isinstance(header, dict):
        raise TokenError("header is not a JSON object")
    if not isinstance(payload, dict):
        raise TokenError("payload is not a JSON object")
    return ("%s.%s" % (head_b, pay_b)).encode("ascii"), header, payload, sig


def _numeric_date(payload, name):
    """Return the claim's value if it is a number, else raise TokenError."""
    if name not in payload:
        return None
    value = payload[name]
    # RFC 7519: exp/nbf/iat MUST be a NumericDate. bool is a subclass of
    # int in Python, so exclude it explicitly.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TokenError(
            "claim %r must be a NumericDate (number), got %r" % (
                name, value))
    return value


def check_token(raw, label, secret=None, issuer=None, audience=None,
                now=None, leeway=60):
    if now is None:
        now = time.time()
    findings = []

    def emit(rule, severity, message):
        findings.append(Finding(label, rule, severity, message))

    signing_input, header, payload, signature = decode_token(raw)
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise TokenError("header has no string 'alg'")

    if alg == "none":
        emit("alg-none", "error",
             "alg is \"none\": an Unsecured JWS provides no integrity "
             "protection (RFC 7518 sec 3.6).")
    elif alg not in HMAC_ALGS:
        emit("unsupported-alg", "error",
             "alg %s is not an HMAC algorithm; jwt-check verifies only "
             "HS256/HS384/HS512 signatures (asymmetric algs need key "
             "material this tool does not handle)." % alg)
    elif secret is not None:
        expected = hmac.new(secret.encode("utf-8"), signing_input,
                            HMAC_ALGS[alg]).digest()
        if not hmac.compare_digest(expected, signature):
            emit("sig-verify-failed", "error",
                 "HMAC signature does not verify with the supplied secret.")
        if len(secret.encode("utf-8")) < MIN_KEY_BYTES[alg]:
            emit("weak-secret", "warning",
                 "secret is %d bytes; RFC 7518 sec 3.2 requires an HMAC "
                 "key at least as large as the hash output (%d bytes for "
                 "%s)." % (len(secret.encode("utf-8")),
                           MIN_KEY_BYTES[alg], alg))

    exp = _numeric_date(payload, "exp")
    nbf = _numeric_date(payload, "nbf")
    iat = _numeric_date(payload, "iat")

    if exp is None:
        emit("missing-exp", "warning",
             "no exp claim: the token never expires (RFC 7519 sec 4.1.4 "
             "makes exp OPTIONAL, so this is a review finding, not a "
             "violation).")
    elif now >= exp + leeway:
        emit("expired", "warning",
             "expired %d seconds ago (exp %d, leeway %ds); RFC 7519 sec "
             "4.1.4 says the token MUST NOT be accepted on or after exp."
             % (now - exp, exp, leeway))

    if nbf is not None and now + leeway < nbf:
        emit("not-yet-valid", "warning",
             "nbf is %d seconds in the future; RFC 7519 sec 4.1.5 says the "
             "token MUST NOT be accepted before nbf." % (nbf - now))

    if iat is not None and iat > now + leeway:
        emit("iat-in-future", "warning",
             "iat is %d seconds in the future (heuristic clock-skew "
             "check; leeway %ds)." % (iat - now, leeway))

    if issuer is not None:
        if payload.get("iss") != issuer:
            emit("issuer-mismatch", "error",
                 "iss is %r, expected %r." % (payload.get("iss"), issuer))

    if audience is not None:
        aud = payload.get("aud")
        ok = (aud == audience) or (
            isinstance(aud, list) and audience in aud)
        if not ok:
            emit("audience-mismatch", "error",
                 "aud is %r, which does not include %r." % (aud, audience))

    return findings


def format_text(results):
    lines = []
    errors = warnings = 0
    for findings in results:
        for f in findings:
            lines.append("%s [%s] %s: %s" % (
                f.token, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("jwt-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("jwt-check: clean")
    return "\n".join(lines), errors, warnings


def format_json(results, errors, warnings):
    return json.dumps({
        "findings": [f.as_dict() for fs in results for f in fs],
        "summary": {"tokens": len(results), "errors": errors,
                    "warnings": warnings},
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="jwt-check",
        description="Validate JSON Web Tokens against RFC 7518/7519. "
                    "Pass raw compact tokens; prefix with @ to read a "
                    "token from a file (@token.txt).")
    p.add_argument("tokens", nargs="+",
                   help="compact JWS token(s), or @file paths")
    p.add_argument("--secret", help="HMAC secret; verifies the signature "
                                    "of HS256/384/512 tokens")
    p.add_argument("--issuer", help="required iss value")
    p.add_argument("--audience", help="required aud value")
    p.add_argument("--now", type=float,
                   help="current time as a Unix timestamp (for testing "
                        "and replay)")
    p.add_argument("--leeway", type=float, default=60,
                   help="clock-skew leeway in seconds (default: 60; "
                        "RFC 7519 allows a few minutes)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ignore = set(args.ignore)
    results = []
    for i, raw in enumerate(args.tokens, 1):
        label = raw
        if raw.startswith("@"):
            try:
                with open(raw[1:], "r", encoding="utf-8") as fh:
                    raw = fh.read().strip()
            except OSError as exc:
                print("jwt-check: cannot read %s: %s" % (raw[1:], exc),
                      file=sys.stderr)
                return 2
        else:
            label = "token %d" % i
        try:
            findings = check_token(
                raw, label, secret=args.secret, issuer=args.issuer,
                audience=args.audience, now=args.now, leeway=args.leeway)
        except TokenError as exc:
            print("jwt-check: %s: %s" % (label, exc), file=sys.stderr)
            return 2
        results.append([f for f in findings if f.rule not in ignore])

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(format_json(results, errors, warnings))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
