import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jwt_check as jc

NOW = 1_800_000_000  # fixed clock for deterministic tests
SECRET = "s" * 32


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(payload, secret=None, alg="HS256", header_extra=None):
    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    head = b64(json.dumps(header).encode())
    pay = b64(json.dumps(payload).encode())
    signing = ("%s.%s" % (head, pay)).encode("ascii")
    if alg == "none":
        return "%s.%s." % (head, pay)
    # unknown algs still get an HMAC-shaped signature; only the header
    # matters for unsupported-alg tests
    digestmod = jc.HMAC_ALGS.get(alg, hashlib.sha256)
    key = (secret or SECRET).encode()
    sig = hmac.new(key, signing, digestmod).digest()
    return "%s.%s.%s" % (head, pay, b64(sig))


def lint(token, **kw):
    kw.setdefault("now", NOW)
    return jc.check_token(token, "t", **kw)


def rules(findings):
    return [f.rule for f in findings]


GOOD_PAYLOAD = {"sub": "u1", "exp": NOW + 3600, "iat": NOW - 10}


class DecodeTests(unittest.TestCase):
    def test_roundtrip(self):
        token = make_token(GOOD_PAYLOAD)
        _, header, payload, sig = jc.decode_token(token)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "u1")
        self.assertTrue(sig)

    def test_two_segments_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc.decode_token("aaa.bbb")

    def test_four_segments_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc.decode_token("a.b.c.d")

    def test_bad_base64_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc.decode_token("!!!.e30i.sig")

    def test_non_json_header_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc.decode_token("%s.e30i.sig" % b64(b"not json"))

    def test_non_object_header_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc.decode_token("%s.e30i.sig" % b64(b"[1,2]"))

    def test_non_object_payload_rejected(self):
        head = b64(json.dumps({"alg": "none"}).encode())
        with self.assertRaises(jc.TokenError):
            jc.decode_token("%s.%s." % (head, b64(b'"str"')))

    def test_missing_alg_rejected(self):
        head = b64(json.dumps({"typ": "JWT"}).encode())
        token = "%s.%s." % (head, b64(b"{}"))
        # structurally decodable, but check_token requires a string alg
        _, header, _, _ = jc.decode_token(token)
        self.assertNotIn("alg", header)
        with self.assertRaises(jc.TokenError):
            jc.check_token(token, "t", now=NOW)


class NumericDateTests(unittest.TestCase):
    def test_valid_number(self):
        self.assertEqual(jc._numeric_date({"exp": 5}, "exp"), 5)

    def test_missing_claim(self):
        self.assertIsNone(jc._numeric_date({}, "exp"))

    def test_string_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc._numeric_date({"exp": "soon"}, "exp")

    def test_bool_rejected(self):
        with self.assertRaises(jc.TokenError):
            jc._numeric_date({"exp": True}, "exp")


class AlgTests(unittest.TestCase):
    def test_alg_none_error(self):
        f = lint(make_token(GOOD_PAYLOAD, alg="none"))
        self.assertEqual(f[0].rule, "alg-none")
        self.assertEqual(f[0].severity, "error")

    def test_unsupported_alg_error(self):
        f = lint(make_token(GOOD_PAYLOAD, alg="RS256"))
        self.assertEqual(f[0].rule, "unsupported-alg")

    def test_hs256_clean(self):
        self.assertEqual(rules(lint(make_token(GOOD_PAYLOAD))), [])

    def test_hs384_clean(self):
        token = make_token(GOOD_PAYLOAD, secret="s" * 48, alg="HS384")
        self.assertEqual(rules(lint(token, secret="s" * 48)), [])

    def test_hs512_clean(self):
        token = make_token(GOOD_PAYLOAD, secret="s" * 64, alg="HS512")
        self.assertEqual(rules(lint(token, secret="s" * 64)), [])


class SignatureTests(unittest.TestCase):
    def test_valid_signature_no_finding(self):
        token = make_token(GOOD_PAYLOAD)
        self.assertNotIn("sig-verify-failed",
                         rules(lint(token, secret=SECRET)))

    def test_wrong_secret_flagged(self):
        token = make_token(GOOD_PAYLOAD)
        f = lint(token, secret="x" * 32)
        self.assertEqual(f[0].rule, "sig-verify-failed")
        self.assertEqual(f[0].severity, "error")

    def test_tampered_payload_flagged(self):
        token = make_token(GOOD_PAYLOAD)
        head, pay, sig = token.split(".")
        bad_pay = b64(json.dumps(dict(GOOD_PAYLOAD, sub="u2")).encode())
        f = lint("%s.%s.%s" % (head, bad_pay, sig), secret=SECRET)
        self.assertIn("sig-verify-failed", rules(f))

    def test_weak_secret_flagged(self):
        token = make_token(GOOD_PAYLOAD, secret="short")
        f = lint(token, secret="short")
        self.assertEqual(f[0].rule, "weak-secret")
        self.assertEqual(f[0].severity, "warning")
        self.assertNotIn("sig-verify-failed", rules(f))

    def test_31_byte_secret_weak_32_ok(self):
        self.assertIn("weak-secret", rules(lint(
            make_token(GOOD_PAYLOAD, secret="s" * 31), secret="s" * 31)))
        self.assertNotIn("weak-secret", rules(lint(
            make_token(GOOD_PAYLOAD, secret="s" * 32), secret="s" * 32)))

    def test_hs384_min_key_48(self):
        token = make_token(GOOD_PAYLOAD, secret="s" * 47, alg="HS384")
        self.assertIn("weak-secret", rules(lint(token, secret="s" * 47)))

    def test_hs512_min_key_64(self):
        token = make_token(GOOD_PAYLOAD, secret="s" * 63, alg="HS512")
        self.assertIn("weak-secret", rules(lint(token, secret="s" * 63)))

    def test_no_secret_means_no_verify(self):
        token = make_token(GOOD_PAYLOAD)
        self.assertEqual(rules(lint(token)), [])


class TimeRuleTests(unittest.TestCase):
    def test_missing_exp_warning(self):
        f = lint(make_token({"sub": "u1"}))
        self.assertEqual(f[0].rule, "missing-exp")
        self.assertEqual(f[0].severity, "warning")

    def test_valid_exp_clean(self):
        self.assertEqual(rules(lint(make_token(GOOD_PAYLOAD))), [])

    def test_expired_flagged(self):
        f = lint(make_token({"exp": NOW - 3600}))
        self.assertEqual(f[0].rule, "expired")

    def test_exp_within_leeway_passes(self):
        self.assertNotIn("expired", rules(lint(
            make_token({"exp": NOW - 30}))))

    def test_exp_past_leeway_flagged(self):
        self.assertIn("expired", rules(lint(
            make_token({"exp": NOW - 120}))))

    def test_custom_leeway(self):
        self.assertIn("expired", rules(lint(
            make_token({"exp": NOW - 30}), leeway=10)))

    def test_nbf_future_flagged(self):
        f = lint(make_token({"exp": NOW + 7200, "nbf": NOW + 3600}))
        self.assertEqual(f[0].rule, "not-yet-valid")

    def test_nbf_within_leeway_passes(self):
        self.assertNotIn("not-yet-valid", rules(lint(
            make_token({"exp": NOW + 7200, "nbf": NOW + 30}))))

    def test_nbf_past_clean(self):
        self.assertEqual(rules(lint(
            make_token({"exp": NOW + 7200, "nbf": NOW - 3600}))), [])

    def test_iat_future_flagged(self):
        f = lint(make_token({"exp": NOW + 7200, "iat": NOW + 600}))
        self.assertEqual(f[0].rule, "iat-in-future")

    def test_iat_within_leeway_passes(self):
        self.assertNotIn("iat-in-future", rules(lint(
            make_token({"exp": NOW + 7200, "iat": NOW + 30}))))

    def test_iat_past_clean(self):
        self.assertEqual(rules(lint(GOOD_PAYLOAD and make_token(
            GOOD_PAYLOAD))), [])

    def test_exp_string_is_malformed(self):
        with self.assertRaises(jc.TokenError):
            lint(make_token({"exp": "tomorrow"}))


class IssuerAudienceTests(unittest.TestCase):
    def test_issuer_match(self):
        self.assertEqual(rules(lint(
            make_token(GOOD_PAYLOAD), issuer=None)), [])
        self.assertNotIn("issuer-mismatch", rules(lint(
            make_token(dict(GOOD_PAYLOAD, iss="me")), issuer="me")))

    def test_issuer_mismatch(self):
        f = lint(make_token(dict(GOOD_PAYLOAD, iss="you")), issuer="me")
        self.assertEqual(f[0].rule, "issuer-mismatch")
        self.assertEqual(f[0].severity, "error")

    def test_issuer_absent(self):
        f = lint(make_token(GOOD_PAYLOAD), issuer="me")
        self.assertIn("issuer-mismatch", rules(f))

    def test_audience_string_match(self):
        self.assertNotIn("audience-mismatch", rules(lint(
            make_token(dict(GOOD_PAYLOAD, aud="api")), audience="api")))

    def test_audience_list_match(self):
        self.assertNotIn("audience-mismatch", rules(lint(
            make_token(dict(GOOD_PAYLOAD, aud=["web", "api"])),
            audience="api")))

    def test_audience_mismatch(self):
        f = lint(make_token(dict(GOOD_PAYLOAD, aud="web")), audience="api")
        self.assertEqual(f[0].rule, "audience-mismatch")

    def test_audience_absent(self):
        f = lint(make_token(GOOD_PAYLOAD), audience="api")
        self.assertIn("audience-mismatch", rules(f))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = jc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD), "--now", str(NOW)])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_warning_only_exit_0(self):
        code, _, _ = self.run_cli(
            [make_token({"sub": "u"}), "--now", str(NOW)])
        self.assertEqual(code, 0)

    def test_fail_on_warning_exit_1(self):
        code, _, _ = self.run_cli(
            [make_token({"sub": "u"}), "--now", str(NOW),
             "--fail-on-warning"])
        self.assertEqual(code, 1)

    def test_error_exit_1(self):
        code, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD, alg="none"), "--now", str(NOW)])
        self.assertEqual(code, 1)
        self.assertIn("alg-none", out)

    def test_malformed_exit_2(self):
        code, _, err = self.run_cli(["not-a-token"])
        self.assertEqual(code, 2)
        self.assertIn("3 dot-separated", err)

    def test_at_file(self):
        path = os.path.join(self.dir, "tok.txt")
        with open(path, "w") as fh:
            fh.write(make_token(GOOD_PAYLOAD) + "\n")
        code, out, _ = self.run_cli(["@" + path, "--now", str(NOW)])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_at_file_missing_exit_2(self):
        code, _, err = self.run_cli(["@" + os.path.join(self.dir, "no.txt")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_multiple_tokens_labeled(self):
        code, out, _ = self.run_cli([
            make_token(GOOD_PAYLOAD, alg="none"),
            make_token({"sub": "u"}),
            "--now", str(NOW)])
        self.assertEqual(code, 1)
        self.assertIn("token 1", out)
        self.assertIn("token 2", out)

    def test_ignore_flag(self):
        code, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD, alg="none"), "--now", str(NOW),
             "--ignore", "alg-none"])
        self.assertEqual(code, 0)
        self.assertNotIn("alg-none", out)

    def test_json_output(self):
        code, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD, alg="none"), "--now", str(NOW),
             "--format", "json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["summary"]["errors"], 1)
        self.assertEqual(parsed["findings"][0]["rule"], "alg-none")
        self.assertEqual(parsed["findings"][0]["token"], "token 1")

    def test_secret_flag_verifies(self):
        code, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD), "--now", str(NOW),
             "--secret", "x" * 32])
        self.assertEqual(code, 1)
        self.assertIn("sig-verify-failed", out)

    def test_output_shape(self):
        _, out, _ = self.run_cli(
            [make_token(GOOD_PAYLOAD, alg="none"), "--now", str(NOW)])
        self.assertIn("token 1 [error] alg-none:", out)


if __name__ == "__main__":
    unittest.main()
