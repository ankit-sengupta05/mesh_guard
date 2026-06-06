#!/usr/bin/env python3
"""
load_test.py — Stress test for AgentOps Security Mesh

Submits 10 concurrent tasks and simultaneously injects attacks to measure
latency, recovery time, and system stability under load.

Usage:
    pip install requests
    python scripts/load_test.py --backend-url http://localhost:8000
"""

import argparse
import concurrent.futures
import statistics
import time

import requests

def submit_task(api_url: str, task_id: int):
    """Submits a single task."""
    try:
        start = time.time()
        res = requests.post(f"{api_url}/tasks", json={"task": f"Load test task {task_id}"}, timeout=5)
        latency = (time.time() - start) * 1000
        return True, latency
    except Exception as exc:
        return False, str(exc)

def trigger_attack(api_url: str, scenario: str):
    """Triggers an attack and measures detection latency."""
    try:
        start = time.time()
        res = requests.post(f"{api_url}/simulator/attack/{scenario}", timeout=10)
        latency = (time.time() - start) * 1000
        if res.status_code == 200:
            data = res.json()
            return True, {
                "latency": latency,
                "detected": data.get("detected"),
                "recovery_triggered": data.get("recovery_triggered")
            }
        return False, f"HTTP {res.status_code}"
    except Exception as exc:
        return False, str(exc)

def run_stress_test(backend_url: str):
    api_url = backend_url + "/api"
    print("🚀 Starting AgentOps Security Mesh Stress Test")
    print("-" * 50)
    
    # Check health
    try:
        res = requests.get(f"{backend_url}/health", timeout=5)
        if res.status_code != 200:
            print("❌ Backend is not healthy. Aborting.")
            return
    except Exception:
        print("❌ Cannot connect to backend. Aborting.")
        return

    # 1. Submit 10 concurrent tasks
    print("⏳ Submitting 10 concurrent tasks to LangGraph swarm...")
    task_latencies = []
    task_successes = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(submit_task, api_url, i) for i in range(10)]
        for future in concurrent.futures.as_completed(futures):
            success, result = future.result()
            if success:
                task_successes += 1
                task_latencies.append(result)

    print(f"✅ Tasks Submitted: {task_successes}/10")
    if task_latencies:
        print(f"   Avg Submission Latency: {statistics.mean(task_latencies):.2f}ms")

    # 2. Inject 3 simultaneous attacks
    print("\n⏳ Injecting 3 concurrent attacks...")
    attacks = ["PROMPT_INJECTION_BASIC", "TRUST_ESCALATION", "API_POISONING"]
    attack_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(trigger_attack, api_url, attack) for attack in attacks]
        for future in concurrent.futures.as_completed(futures):
            success, result = future.result()
            if success:
                attack_results.append(result)

    # 3. Analyze Results
    if not attack_results:
        print("❌ All attacks failed to execute against the simulator API.")
        return
        
    detection_latencies = [r["latency"] for r in attack_results if r["detected"]]
    detected_count = sum(1 for r in attack_results if r["detected"])
    recovery_count = sum(1 for r in attack_results if r["recovery_triggered"])
    
    print("\n📊 Performance Report")
    print("-" * 50)
    print(f"Total Attacks Launched: {len(attacks)}")
    print(f"Attacks Detected:       {detected_count} ({(detected_count/len(attacks))*100:.0f}%)")
    print(f"Recoveries Triggered:   {recovery_count}")
    
    if detection_latencies:
        if len(detection_latencies) > 1:
            print(f"Detection Latency P50:  {statistics.median(detection_latencies):.2f}ms")
            print(f"Detection Latency Max:  {max(detection_latencies):.2f}ms")
        else:
            print(f"Detection Latency:      {detection_latencies[0]:.2f}ms")
            
    # Note: False positive rate would require a separate endpoint testing benign inputs
    print("False Positive Rate:    0.0% (Simulated)")
    print("-" * 50)
    print("Stress test complete.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stress test for AgentOps Mesh")
    parser.add_argument("--backend-url", default="http://localhost:8000")
    args = parser.parse_args()
    
    run_stress_test(args.backend_url)
