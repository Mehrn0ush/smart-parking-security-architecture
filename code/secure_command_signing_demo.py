#!/usr/bin/env python3
"""
Small teaching example for gate-control command authentication.

This demo uses HMAC plus a nonce and timestamp window to show:
- command integrity
- source authentication
- replay resistance

Production systems should prefer device identities backed by X.509,
hardware-protected keys, and mutual TLS. This example is intentionally
small so it is easy to study.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict


@dataclass
class GateCommand:
    device_id: str
    action: str
    gate_id: str
    nonce: str
    timestamp: int


def canonical_payload(command: GateCommand) -> bytes:
    return json.dumps(asdict(command), sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_secret_from_env() -> bytes:
    secret = os.environ.get("SMART_PARKING_GATE_DEMO_SECRET")
    if not secret:
        raise SystemExit(
            "Set SMART_PARKING_GATE_DEMO_SECRET before running this demo. "
            "Example: export SMART_PARKING_GATE_DEMO_SECRET='change-me'"
        )
    return secret.encode("utf-8")


def sign_command(command: GateCommand, secret: bytes) -> str:
    return hmac.new(secret, canonical_payload(command), hashlib.sha256).hexdigest()


def verify_command(
    command: GateCommand,
    signature: str,
    seen_nonces: set[str],
    secret: bytes,
    max_age_seconds: int = 30,
) -> tuple[bool, str]:
    now = int(time.time())
    if abs(now - command.timestamp) > max_age_seconds:
        return False, "stale-or-future-command"
    if command.nonce in seen_nonces:
        return False, "replay-detected"
    expected = sign_command(command, secret)
    if not hmac.compare_digest(expected, signature):
        return False, "signature-mismatch"
    seen_nonces.add(command.nonce)
    return True, "accepted"


def main() -> None:
    secret = load_secret_from_env()
    seen_nonces: set[str] = set()
    command = GateCommand(
        device_id="gateway-01",
        action="OPEN_GATE",
        gate_id="north-entry",
        nonce=secrets.token_hex(8),
        timestamp=int(time.time()),
    )
    signature = sign_command(command, secret)
    ok, reason = verify_command(command, signature, seen_nonces, secret)
    print(json.dumps({"command": asdict(command), "verification": reason, "accepted": ok}, indent=2))

    replay_ok, replay_reason = verify_command(command, signature, seen_nonces, secret)
    print(json.dumps({"replay_verification": replay_reason, "accepted": replay_ok}, indent=2))


if __name__ == "__main__":
    main()
