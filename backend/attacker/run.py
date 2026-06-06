"""
AgentOps Security Mesh — Mock Attacker Service.

Simulates an adversarial agent sending attack payloads to the backend.
Used by the mock-attacker Docker Compose service with --profile attack.

Runs on a configurable interval, cycling through attack types.
Results are logged to stdout and Redis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("mock-attacker")

TARGET_URL = os.getenv("TARGET_URL", "http://localhost:8000")
INTERVAL = int(os.getenv("ATTACK_INTERVAL_SECONDS", "30"))
API_KEY = os.getenv("API_KEY", "dev-api-key")

ATTACK_TYPES = ["prompt_injection", "memory_poison", "identity_spoof", "tool_hijack"]


async def run_attack(client: httpx.AsyncClient, attack_type: str) -> Dict[str, Any]:
    """Send a single attack to the simulation endpoint."""
    payload = {
        "attack_type": attack_type,
        "intensity": random.randint(1, 3),
    }
    try:
        response = await client.post(
            f"{TARGET_URL}/api/v1/simulation/attack",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=10.0,
        )
        result = response.json()
        status_icon = "🛡️ BLOCKED" if result.get("blocked") else "⚠️ PASSED"
        logger.info(
            "[%s] %s | type=%s | confidence=%.2f",
            status_icon,
            attack_type.upper(),
            attack_type,
            result.get("confidence", 0),
        )
        return result
    except httpx.ConnectError:
        logger.warning("Backend not reachable at %s — retrying in %ds", TARGET_URL, INTERVAL)
        return {}
    except Exception as exc:
        logger.error("Attack failed: %s", exc)
        return {}


async def main() -> None:
    """Main attack loop — runs indefinitely at INTERVAL seconds."""
    logger.info("═══ Mock Attacker Starting ═══")
    logger.info("Target: %s | Interval: %ds", TARGET_URL, INTERVAL)

    # Wait for backend to be ready
    async with httpx.AsyncClient() as client:
        for _ in range(30):
            try:
                r = await client.get(f"{TARGET_URL}/health", timeout=3.0)
                if r.status_code == 200:
                    logger.info("✓ Backend is ready — starting attack loop")
                    break
            except Exception:
                pass
            logger.info("Waiting for backend...")
            await asyncio.sleep(3)

    # Attack loop
    async with httpx.AsyncClient() as client:
        attack_count = 0
        while True:
            attack_type = ATTACK_TYPES[attack_count % len(ATTACK_TYPES)]
            logger.info(
                "── Attack #%d | type=%s ──",
                attack_count + 1,
                attack_type,
            )
            await run_attack(client, attack_type)
            attack_count += 1
            await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
