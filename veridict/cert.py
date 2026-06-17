"""
veridict.cert — a tamper-evident certificate of what was actually verified.

A verdict is more useful if it can't be quietly edited after the fact. `certify` produces
a canonical record of the run plus a SHA-256 digest; with a key it adds an HMAC signature.
`verify_certificate` recomputes both, so any change to a claim, verdict, or evidence is
detectable. Stdlib only (hashlib/hmac) — symmetric/keyed; asymmetric signing is left to a
caller that wants it.

    cert = certify(results, overall, key=os.environ.get("VERIDICT_KEY"))
    ok, why = verify_certificate(cert, key=os.environ.get("VERIDICT_KEY"))
"""
from __future__ import annotations

import hashlib
import hmac
import json

__version__ = "0.2.0"

# fields that are part of the attested payload (duration_ms is nondeterministic -> excluded)
_PAYLOAD_KEYS = ("actor", "action", "claim", "verdict", "evidence", "checked_at")


def _payload(results, overall):
    return {"tool": "veridict", "version": __version__, "overall": overall,
            "steps": [{k: r.get(k) for k in _PAYLOAD_KEYS} for r in results]}


def _canonical(payload):
    # sorted keys + no whitespace = stable bytes regardless of dict order
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def certify(results, overall, key=None):
    """Return a certificate dict: the attested payload + its sha256 digest, and an HMAC
    signature if `key` is given."""
    payload = _payload(results, overall)
    blob = _canonical(payload)
    cert = {**payload, "digest_sha256": hashlib.sha256(blob).hexdigest(), "signed": False}
    if key:
        k = key.encode() if isinstance(key, str) else key
        cert["signature_hmac_sha256"] = hmac.new(k, blob, hashlib.sha256).hexdigest()
        cert["signed"] = True
    return cert


def verify_certificate(cert, key=None):
    """Recompute the digest (and HMAC if signed) from the certificate's own payload.
    Returns (ok, reason). Detects any post-hoc edit to a claim/verdict/evidence."""
    payload = {k: cert.get(k) for k in ("tool", "version", "overall", "steps")}
    blob = _canonical(payload)
    if hashlib.sha256(blob).hexdigest() != cert.get("digest_sha256"):
        return False, "digest mismatch — certificate payload was altered"
    if cert.get("signed"):
        if not key:
            return False, "certificate is signed but no key was provided to verify it"
        k = key.encode() if isinstance(key, str) else key
        expected = hmac.new(k, blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, cert.get("signature_hmac_sha256", "")):
            return False, "HMAC signature mismatch — wrong key or tampered certificate"
    return True, "certificate intact" + (" and signature valid" if cert.get("signed") else "")
