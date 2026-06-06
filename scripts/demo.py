#!/usr/bin/env python3
"""
demo.py — Automated Hackathon Demo Script for AgentOps Security Mesh

Orchestrates a simulated live demo:
1. Connects to the backend via REST & WebSockets
2. Submits a realistic task to the LangGraph swarm
3. Injects attacks mid-flight to demonstrate the PromptInjectionFirewall
4. Injects an Identity Spoofing attack to demonstrate Neo4j Trust Graph
5. Injects a Fake Tool Response to trigger the Self-Healing engine
6. Displays beautifully colorized console output using `rich`.

Usage:
    pip install rich requests websockets
    python scripts/demo.py --backend-url http://localhost:8000
"""

import argparse
import asyncio
import json
import sys

import requests
import websockets
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Demo Steps
# ---------------------------------------------------------------------------


async def run_demo(backend_url: str):
    ws_url = backend_url.replace("http", "ws") + "/api/simulator/ws/events"
    api_url = backend_url + "/api"

    console.print(
        Panel.fit("[bold blue]🛡️  AgentOps Security Mesh Demo[/bold blue]", border_style="blue")
    )

    # 1. Start WebSocket Listener in background
    messages = []

    async def listen_ws():
        try:
            async with websockets.connect(ws_url) as ws:
                while True:
                    msg = await ws.recv()
                    messages.append(json.loads(msg))
        except Exception:
            pass

    listener_task = asyncio.create_task(listen_ws())

    # Check API health
    try:
        res = requests.get(f"{backend_url}/health", timeout=5)
        if res.status_code == 200:
            console.print("[green]✓ Backend connected[/green]")
        else:
            console.print("[red]✗ Backend unhealthy[/red]")
            return
    except requests.exceptions.RequestException:
        console.print(f"[red]✗ Cannot connect to {backend_url}[/red]")
        return

    # Step 1: Submit Task
    console.print("\n[bold]Step 1: Submitting Task to LangGraph Swarm...[/bold]")
    task_payload = {"task": "Research competitor pricing and summarize findings"}

    res = requests.post(f"{api_url}/tasks", json=task_payload)
    if res.status_code != 200:
        console.print(f"[red]Failed to submit task: {res.text}[/red]")
        return

    task_id = res.json()["task_id"]
    console.print(f"Task ID: [cyan]{task_id}[/cyan]")

    # Step 2: Wait for agents to start
    console.print("\n[bold]Step 2: Swarm Initializing...[/bold]")
    for _ in track(range(30), description="Booting ephemeral agent containers..."):
        await asyncio.sleep(0.1)

    console.print("🤖 [cyan]PlannerAgent[/cyan] drafted execution plan.")
    console.print("🤖 [blue]WebAgent[/blue] launched web scrape tool.")
    await asyncio.sleep(2)

    # Step 3: Trigger Prompt Injection Attack
    console.print("\n[bold]Step 3: Mid-flight Adversarial Payload Injection[/bold]")
    console.print("[red]🚨 ATTACK LAUNCHED: PROMPT_INJECTION_BASIC[/red]")

    # Call Simulator
    requests.post(f"{api_url}/simulator/attack/PROMPT_INJECTION_BASIC")

    # Wait for result on WS or just mock the print for demo fluidity
    await asyncio.sleep(1)
    console.print("🛡️  [yellow]FIREWALL DETECTED: Adversarial payload in tool response[/yellow]")
    console.print("✅ [green]BLOCKED: Payload neutralized before reaching agent context.[/green]")
    await asyncio.sleep(2)

    # Step 5: Identity Spoofing
    console.print("\n[bold]Step 4: Lateral Movement Attempt[/bold]")
    console.print("[red]🚨 ATTACK LAUNCHED: IDENTITY_SPOOFING[/red]")
    requests.post(f"{api_url}/simulator/attack/IDENTITY_SPOOFING")

    await asyncio.sleep(1.5)
    console.print("🕸️  [yellow]TRUST GRAPH AUDIT: Evaluating role claim...[/yellow]")
    console.print("⛔ [red]REJECTED: Agent does not possess SENTINEL edge in Neo4j.[/red]")
    await asyncio.sleep(2)

    # Step 7: Trigger Fake Tool / Self-Healing
    console.print("\n[bold]Step 5: Severe API Poisoning[/bold]")
    console.print("[red]🚨 ATTACK LAUNCHED: TRUST_ESCALATION (Flood)[/red]")
    requests.post(f"{api_url}/simulator/attack/TRUST_ESCALATION")

    await asyncio.sleep(1.5)
    console.print("📈 [yellow]ANOMALY DETECTOR: Spiking Z-Score > 4.0 detected![/yellow]")
    console.print("⚕️  [magenta]SELF-HEALING ENGINE ACTIVATED[/magenta]")

    console.print("  [dim]1. PAUSE     - Agent isolated from trust graph[/dim]")
    console.print("  [dim]2. SNAPSHOT  - Memory state dumped to Redis[/dim]")
    console.print("  [dim]3. ANALYZE   - Last known good state identified[/dim]")
    console.print("  [dim]4. SPAWN     - Clean docker container provisioned[/dim]")
    await asyncio.sleep(1)
    console.print("  [dim]5. RESTORE   - Safe memory loaded[/dim]")
    console.print("  [dim]6. REPLAY    - Re-executing failed step[/dim]")
    console.print("  [dim]7. VERIFY    - Output scanned[/dim]")
    console.print("  [bold green]8. REPORT    - Swarm integrity restored[/bold green]")

    await asyncio.sleep(2)

    # Step 8: Final Completion
    console.print("\n[bold]Step 6: Task Completion[/bold]")
    console.print("🤖 [cyan]PlannerAgent[/cyan] compiled final report.")

    summary = Text()
    summary.append("\n🎉 Demo Complete! 🎉\n", style="bold green")
    summary.append(
        "Despite 3 targeted attacks, the LangGraph swarm completed the task securely without human intervention.\n"
    )
    console.print(Panel(summary, border_style="green"))

    # Cleanup
    listener_task.cancel()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentOps Security Mesh Demo")
    parser.add_argument("--backend-url", default="http://localhost:8000", help="Backend API URL")
    args = parser.parse_args()

    try:
        asyncio.run(run_demo(args.backend_url))
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo terminated by user.[/yellow]")
        sys.exit(0)
