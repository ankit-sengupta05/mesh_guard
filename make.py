#!/usr/bin/env python3
import sys
import subprocess
import os
import shutil

def run(cmd, cwd=None):
    print(f"Running: {cmd}", flush=True)
    subprocess.run(cmd, shell=True, cwd=cwd, check=True)

target = sys.argv[1] if len(sys.argv) > 1 else "help"
root = os.path.dirname(os.path.abspath(__file__))

if target == "help":
    print("Commands: install, infra-up, stack-up, stack-down, attack-demo, load-test, clean")

elif target == "install":
    run("pip install -r requirements.txt", cwd=os.path.join(root, "backend"))
    run("npm install", cwd=os.path.join(root, "frontend"))
    if not os.path.exists(".env"):
        shutil.copy(".env.example", ".env")

elif target == "infra-up":
    run("docker-compose up -d redis neo4j")

elif target == "stack-up":
    run("docker-compose up --build -d")
    print("Frontend: http://localhost:5173")
    print("Backend: http://localhost:8000")

elif target == "stack-down":
    run("docker-compose down")

elif target == "attack-demo":
    run("python scripts/demo.py --backend-url http://localhost:8000")

elif target == "load-test":
    run("python scripts/load_test.py --backend-url http://localhost:8000")

elif target == "clean":
    run("docker-compose down -v --remove-orphans")

else:
    print(f"Unknown target: {target}")
