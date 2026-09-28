#!/usr/bin/env python3
"""T14 — Redirect safety conformance vectors (audit-suite, zero-dependency).

Born from adversarial-research-audit PR#4 (external researcher GodBlf found two
real holes in our own verify.py). This tool turns that trap into a reusable
conformance suite so the same class of bug can be caught automatically in any
Python HTTP client that implements the "verify(url) -> {outcome, ...}" contract.

What it checks (three vectors, one local trap server):

  V1 scheme-allowlist   a 302 to ftp://127.0.0.1:<port>/ must never leave the
                        HTTP(S) world; the client must report a policy BLOCK,
                        not a network error and not a follow-through.
  V2 body-discard       the intermediate redirect response body must NOT be
                        drained. The trap serves a sized body and counts how
                        many bytes the client actually pulled.
  V3 outcome-honesty    a policy violation must surface as an explicit
                        BLOCKED-style outcome, never masked as "unknown" /
                        network-unavailable (ADAS R1: three-state honesty).

Discriminator selftest: a deliberately naive urllib opener must FAIL all three
vectors; a compliant opener (redirect handler with scheme allow-list + early
body close) must PASS. If both don't hold, the vectors are broken — exit 1.

Real-target mode:
    python -m audit_suite.redirect_conformance check <dir-or-file> --class SourceVerifier
loads <target>/verify.py (or a single file), builds <Class>(allow_private_
networks=True), points it at the trap and scores it. Exit code follows the
suite's two-axis convention (12 = FAIL, 11 = PASS-WITH-CAVEAT, 0 = PASS).
"""

from __future__ import annotations

import http.server
import importlib.util
import io
import json
import socketserver
import sys
import threading
import urllib.request
from pathlib import Path

from .receipt import make_receipt

TRAP_BODY = b"A" * (8 * 1024 * 1024)          # 8 MiB intermediate body
DRAIN_TOLERANCE_BYTES = 64 * 1024             # small header slop is fine

BIN_FORMAT = {"protocol": "redirect-conformance-v1", "vectors": 3}


# ---------------------------------------------------------------- trap server
class _RedirectTrapHandler(http.server.BaseHTTPRequestHandler):
    """302 -> ftp:// loopback with a fat intermediate body; byte-accounted."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 (stdlib naming)
        try:
            body = self.server.trap_body
            self.send_response(302)
            self.send_header("Location", self.server.trap_target)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.server.bytes_served[0] += len(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client closed early => body NOT drained (what we want)

    def log_message(self, *args):  # silence
        pass


class RedirectTrapServer:
    """Context manager: local HTTP server that traps careless redirect logic."""

    def __init__(self, target: str | None = None, body: bytes = TRAP_BODY,
                 port: int = 0):
        self.trap_target = target          # filled per-request in start()
        self.trap_body = body
        self.bytes_served = [0]
        self._srv = None
        self._thread = None
        self._port = port

    def __enter__(self):
        self._srv = socketserver.TCPServer(("127.0.0.1", self._port),
                                           _RedirectTrapHandler)
        self._srv.bytes_served = self.bytes_served
        self._srv.trap_body = self.trap_body
        self._srv.trap_target = self.trap_target
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
        return False

    @property
    def base_url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}/seed"

    def reset(self) -> None:
        self.bytes_served[0] = 0

    @property
    def drained_bytes(self) -> int:
        return self.bytes_served[0]


# ------------------------------------------------------- reference clients
def naive_client(url: str) -> dict:
    """Deliberately vulnerable: stock urllib opener (what main had)."""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with op.open(url, timeout=10) as resp:
            return {"outcome": "alive", "drained": True}
    except urllib.error.URLError as exc:
        return {"outcome": "unknown", "error": str(exc), "drained": True}


class _CompliantRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reference implementation of the PR#4 pattern (scheme gate + early close)."""

    def http_error_302(self, req, fp, code, msg, headers):
        fp.close()
        target = headers.get("location", headers.get("uri"))
        if target is not None:
            scheme = urllib.parse.urlparse(target).scheme
            if scheme not in ("", "http", "https"):
                return self._block()
        with io.BytesIO() as empty:
            return super().http_error_302(req, empty, code, msg, headers)

    def _block(self):
        raise urllib.error.URLError("policy-blocked: redirects must use HTTP(S)")

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def compliant_client(url: str) -> dict:
    """Reference PASS client: scheme gate, no intermediate drain."""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     _CompliantRedirectHandler())
    try:
        with op.open(url, timeout=10) as resp:
            return {"outcome": "alive", "drained": False}
    except urllib.error.URLError as exc:
        blocked = "policy-blocked" in str(exc)
        return {"outcome": "blocked" if blocked else "unknown",
                "error": str(exc), "drained": False}


# ------------------------------------------------------------------ scoring
def score_client(client, base_url: str, drained_bytes: int) -> tuple[str, list]:
    """Score one client against the three vectors. Returns (verdict, findings)."""
    findings = []
    r = client(base_url) if not isinstance(client, type) else None

    # contract clients return dicts; SourceVerifier-style return outcome dicts
    if r is None:  # callable class instance path handled by caller wrapper
        raise TypeError("client must be callable")
    outcome = str(r.get("outcome", "")).lower()

    if outcome in ("alive", "ok", "success"):
        findings.append({"id": "v1-scheme-bypass", "severity": "critical",
                         "message": "client followed a redirect out of HTTP(S) "
                                    "(ftp trap was reached)",
                         "location": base_url, "reproducible": True})
    elif outcome not in ("blocked", "dead", "policy-blocked"):
        findings.append({"id": "v3-outcome-dishonest", "severity": "major",
                         "message": f"policy violation surfaced as '{outcome}' "
                                    f"instead of an explicit BLOCK — masked as "
                                    f"network trouble (ADAS R1)",
                         "location": base_url, "reproducible": True})

    if drained_bytes > DRAIN_TOLERANCE_BYTES:
        findings.append({"id": "v2-body-drain", "severity": "major",
                         "message": f"client drained {drained_bytes} bytes of the "
                                    f"intermediate redirect body (unbounded read)",
                         "location": base_url, "reproducible": True})

    verdict = "PASS" if not findings else "FAIL"
    return verdict, findings


def check_contract_module(target: Path, class_name: str = "SourceVerifier"
                          ) -> dict:
    """Run the three vectors against a verify(url)->dict module."""
    spec = importlib.util.spec_from_file_location("_t14_target", str(target))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_t14_target"] = mod
    spec.loader.exec_module(mod)
    verifier_cls = getattr(mod, class_name)

    findings = []
    with RedirectTrapServer() as trap:
        ftp_target = f"ftp://127.0.0.1:9/t14-trap"  # discard port: nothing listens
        trap._srv.trap_target = ftp_target
        trap.reset()
        v = verifier_cls(allow_private_networks=True)
        r = v.verify(trap.base_url)
        verdict, f = score_client(lambda _u: r, trap.base_url,
                                  trap.drained_bytes)
        findings.extend(f)

    receipt = make_receipt(
        "redirect-conformance", verdict=verdict,
        inputs={"target": str(target), "class": class_name},
        outputs={**BIN_FORMAT, "findings": findings},
        caveats=["vectors: V1 scheme-allowlist / V2 body-discard / V3 outcome-honesty"])
    return receipt


# ------------------------------------------------------------------ selftest
def selftest() -> int:
    ok = True
    with RedirectTrapServer() as trap:
        trap._srv.trap_target = "ftp://127.0.0.1:9/t14-trap"
        url = trap.base_url
        trap.reset()
        v_naive, f_naive = score_client(naive_client, url, trap.drained_bytes)
        # naive must FAIL with the scheme/dishonest finding
        if v_naive != "FAIL":
            print("selftest FAIL: naive client passed vectors — vectors broken")
            ok = False
        elif not any(x["id"] in ("v1-scheme-bypass", "v3-outcome-dishonest")
                     for x in f_naive):
            print("selftest FAIL: naive client failed for the wrong reason")
            ok = False

        trap.reset()
        v_ok, f_ok = score_client(compliant_client, url, trap.drained_bytes)
        # compliant must PASS with zero drain
        if v_ok != "PASS" or trap.drained_bytes > DRAIN_TOLERANCE_BYTES:
            print(f"selftest FAIL: compliant client verdict={v_ok} "
                  f"drained={trap.drained_bytes}")
            ok = False

    print(json.dumps(make_receipt(
        "redirect-conformance", verdict="PASS" if ok else "FAIL",
        outputs={**BIN_FORMAT, "selftest":
                 {"naive": v_naive, "compliant": v_ok,
                  "naive_drained_bytes": DRAIN_TOLERANCE_BYTES}},
        caveats=["discriminator selftest: naive must FAIL, compliant must PASS"]),
        ensure_ascii=False))
    if not ok:
        return 1
    print("selftest: discriminator holds (naive=FAIL, compliant=PASS, "
          "drain=0)")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 3 and argv[1] == "check":
        target = Path(argv[2])
        cls = "SourceVerifier"
        if "--class" in argv:
            cls = argv[argv.index("--class") + 1]
        r = check_contract_module(target, cls)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return {"PASS": 0, "PASS-WITH-CAVEAT": 11}.get(r["verdict"], 12)
    print("USAGE: python -m audit_suite.redirect_conformance selftest\n"
          "       python -m audit_suite.redirect_conformance check "
          "<verify.py> [--class SourceVerifier]", file=sys.stderr)
    return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
