"""Opt-in TPM 2.0 PCR quote for the local lab.

The AK public key and expected PCR bytes must be pinned by the operator before
the service starts. A successful quote attests those PCR values and a fresh
nonce bound to the checked source manifest; it does not attest Python memory.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Callable


PCR_SELECTION = re.compile(r"sha256:(?:[0-9]|1[0-9]|2[0-3])(?:,(?:[0-9]|1[0-9]|2[0-3]))*")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
Runner = Callable[..., subprocess.CompletedProcess]


def required() -> bool:
    return os.environ.get("AGENTSENTINEL_TPM_REQUIRED") == "1"


def availability() -> dict:
    if sys.platform != "linux":
        return {"available": False, "reason": "LINUX_TPM_HOST_REQUIRED"}
    if not (Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists()):
        return {"available": False, "reason": "TPM_DEVICE_UNAVAILABLE"}
    if not shutil.which("tpm2_quote") or not shutil.which("tpm2_checkquote"):
        return {"available": False, "reason": "TPM2_TOOLS_UNAVAILABLE"}
    return {"available": True, "reason": "TPM_QUOTE_TOOLS_READY"}


def _configuration() -> tuple[Path, Path, str, str, str] | None:
    values = [os.environ.get(key, "") for key in (
        "AGENTSENTINEL_TPM_AK_CONTEXT", "AGENTSENTINEL_TPM_TRUSTED_AK_PEM",
        "AGENTSENTINEL_TPM_AK_SHA256", "AGENTSENTINEL_TPM_EXPECTED_PCR_SHA256",
        "AGENTSENTINEL_TPM_PCR_SELECTION")]
    if not all(values):
        return None
    context, public, ak_digest, pcr_digest, selection = values
    if not HEX_SHA256.fullmatch(ak_digest) or not HEX_SHA256.fullmatch(pcr_digest):
        return None
    if not PCR_SELECTION.fullmatch(selection) or len(set(selection.split(':')[1].split(','))) != len(selection.split(':')[1].split(',')):
        return None
    return Path(context), Path(public), ak_digest, pcr_digest, selection


def quote_for_run(run_id: str, manifest_sha256: str, *, runner: Runner = subprocess.run) -> dict:
    """Return signed evidence on success; otherwise a reason and no hardware claim."""
    unavailable = availability()
    if not unavailable["available"]:
        return {"valid": False, "hardware_attested": False, "reason": unavailable["reason"]}
    config = _configuration()
    if config is None or not HEX_SHA256.fullmatch(manifest_sha256):
        return {"valid": False, "hardware_attested": False, "reason": "TPM_TRUST_BASELINE_UNCONFIGURED"}
    context, public, trusted_ak, expected_pcr, selection = config
    try:
        pem = public.read_bytes()
        if not context.is_file() or hashlib.sha256(pem).hexdigest() != trusted_ak:
            return {"valid": False, "hardware_attested": False, "reason": "TPM_AK_TRUST_MISMATCH"}
        nonce = hashlib.sha256(secrets.token_bytes(32) + run_id.encode() + bytes.fromhex(manifest_sha256)).hexdigest()
        with tempfile.TemporaryDirectory(prefix="agentsentinel-tpm-") as directory:
            base = Path(directory)
            message, signature, pcrs = (base / name for name in ("quote.msg", "quote.sig", "quote.pcrs"))
            quote = runner(["tpm2_quote", "-c", str(context), "-l", selection, "-q", nonce,
                            "-m", str(message), "-s", str(signature), "-o", str(pcrs), "-g", "sha256"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=8, check=False)
            if quote.returncode != 0:
                return {"valid": False, "hardware_attested": False, "reason": "TPM_QUOTE_FAILED"}
            evidence = [path.read_bytes() for path in (message, signature, pcrs)]
            if any(not item or len(item) > 65536 for item in evidence):
                return {"valid": False, "hardware_attested": False, "reason": "TPM_QUOTE_MALFORMED"}
            if hashlib.sha256(evidence[2]).hexdigest() != expected_pcr:
                return {"valid": False, "hardware_attested": False, "reason": "TPM_PCR_BASELINE_MISMATCH"}
            checked = runner(["tpm2_checkquote", "-u", str(public), "-m", str(message),
                              "-s", str(signature), "-f", str(pcrs), "-g", "sha256",
                              "-q", nonce, "-l", selection],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=8, check=False)
            if checked.returncode != 0:
                return {"valid": False, "hardware_attested": False, "reason": "TPM_QUOTE_VERIFICATION_FAILED"}
            return {"valid": True, "hardware_attested": True, "reason": "TPM_PCR_QUOTE_VERIFIED",
                    "mode": "TPM_PCR_QUOTE_AND_SOFTWARE", "manifest_sha256": manifest_sha256,
                    "nonce": nonce, "pcr_selection": selection, "ak_public_sha256": trusted_ak,
                    "pcr_sha256": expected_pcr, "ak_public_pem": pem.decode("ascii"),
                    "quote_b64": base64.b64encode(evidence[0]).decode(),
                    "signature_b64": base64.b64encode(evidence[1]).decode(),
                    "pcr_b64": base64.b64encode(evidence[2]).decode()}
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return {"valid": False, "hardware_attested": False, "reason": "TPM_QUOTE_UNAVAILABLE"}


def verify_exported_quote(evidence: dict, *, trusted_ak_sha256: str,
                          expected_pcr_sha256: str, runner: Runner = subprocess.run) -> bool:
    """Offline verifier. Caller must supply independent AK and PCR trust pins."""
    if not HEX_SHA256.fullmatch(trusted_ak_sha256) or not HEX_SHA256.fullmatch(expected_pcr_sha256):
        return False
    try:
        if not evidence.get("hardware_attested") or not PCR_SELECTION.fullmatch(evidence["pcr_selection"]):
            return False
        nonce = evidence["nonce"]
        if not HEX_SHA256.fullmatch(nonce):
            return False
        pem = evidence["ak_public_pem"].encode("ascii")
        quote, sig, pcr = [base64.b64decode(evidence[key], validate=True) for key in
                           ("quote_b64", "signature_b64", "pcr_b64")]
        if (hashlib.sha256(pem).hexdigest() != trusted_ak_sha256 or
                hashlib.sha256(pcr).hexdigest() != expected_pcr_sha256 or
                any(not part or len(part) > 65536 for part in (quote, sig, pcr))):
            return False
        with tempfile.TemporaryDirectory(prefix="agentsentinel-tpm-verify-") as directory:
            base = Path(directory)
            for name, value in (("ak.pem", pem), ("quote.msg", quote), ("quote.sig", sig), ("quote.pcrs", pcr)):
                (base/name).write_bytes(value)
            checked = runner(["tpm2_checkquote", "-u", str(base/"ak.pem"), "-m", str(base/"quote.msg"),
                              "-s", str(base/"quote.sig"), "-f", str(base/"quote.pcrs"),
                              "-g", "sha256", "-q", nonce, "-l", evidence["pcr_selection"]],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=8, check=False)
            return checked.returncode == 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        return False
