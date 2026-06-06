<div align="center">
  <img src="https://raw.githubusercontent.com/ankit-sengupta05/mesh_guard/main/frontend/public/vite.svg" width="100" />
  <h1 align="center">🛡️ AgentOps Security Mesh</h1>
  <p align="center">
    <strong>The Self-Healing, Graph-Trusted, AI Swarm Framework</strong>
    <br />
    A resilient LangGraph-based orchestrator secured by a Prompt Injection Firewall, Neo4j Trust Graphs, and real-time Anomaly Detection.
  </p>

  <p align="center">
    <a href="https://github.com/ankit-sengupta05/mesh_guard/actions"><img src="https://img.shields.io/github/actions/workflow/status/ankit-sengupta05/mesh_guard/ci.yml?branch=main&label=Build%20%26%20Security&style=for-the-badge&color=2ea44f" alt="Build Status"></a>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"></a>
    <a href="https://react.dev"><img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"></a>
    <a href="https://neo4j.com"><img src="https://img.shields.io/badge/Neo4j-Trust%20Graph-018bff?style=for-the-badge&logo=neo4j&logoColor=white" alt="Neo4j"></a>
    <a href="https://redis.io"><img src="https://img.shields.io/badge/Redis-Memory-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis"></a>
  </p>
</div>

<hr />

## ✨ Features

- 🧠 **LangGraph Swarm Orchestration**: Dynamic creation and interaction of agents (Planner, Coder, Validator, Sentinel).
- 🔥 **Prompt Injection Firewall**: Real-time evaluation of inputs against heuristic and LLM-based injection patterns.
- 🕸️ **Neo4j Trust Graph**: Dynamic trust modeling. Agents earn or lose trust based on output validity. Below-threshold agents are sandboxed.
- 💊 **Self-Healing Daemon**: Automated snapshotting and rollback of compromised agents using isolated memory boundaries.
- 🎯 **Attack Simulator**: Built-in endpoints to safely simulate API poisonings, context window overflows, and prompt injections to test system resilience.
- ⚙️ **Hot-Swappable LLMs**: Instantly switch between OpenAI, Azure, and local LM Studio models mid-execution via the UI.
- 🛡️ **Iron-Clad Git Hooks**: Fully automated secret masking, trailing-whitespace purging, and Babel/Flake8 syntax compilation on every commit.

---

## 🏗️ Architecture Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | React, Vite, Zustand, Tailwind | Dashboard for monitoring agents, threats, and trust graphs. |
| **Backend** | FastAPI, Python 3.11 | API Gateway, Swarm Control, and Security Event routing. |
| **AI Engine** | LangGraph, LangChain | Managing agent state, cyclic interactions, and tool calling. |
| **Trust Layer** | Neo4j | Graph database representing nodes (agents) and edges (trust metrics). |
| **Memory** | Redis | Ephemeral and snapshotted memory management for rollback capabilities. |

---

## 🚀 Getting Started

### 1️⃣ Prerequisites

Ensure you have the following installed:
- **Node.js** (v20+)
- **Python** (v3.11+)
- **Redis** Server (Running on port `6379`)
- **Neo4j** Database (Running locally or via AuraDB)

### 2️⃣ Installation

Clone the repository and set up the environments:

```bash
# Clone the repository
git clone https://github.com/ankit-sengupta05/mesh_guard.git
cd mesh_guard

# Set up Python Backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# Set up React Frontend
cd frontend
npm install
cd ..
```

### 3️⃣ Environment Variables

Copy the example environment file and configure your keys:

```bash
cp .env.example .env
```
*Ensure you update the `.env` file with your `OPENAI_API_KEY`, `NEO4J_URI`, and `REDIS_URL`.*

### 4️⃣ Run the Application

You can start both the backend and frontend development servers.

**Start the Backend:**
```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

**Start the Frontend:**
```bash
cd frontend
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

---

## 🔌 API Endpoints

The FastAPI backend exposes the following core endpoints to manage the swarm and security mesh:

### 🧩 Swarm & Agents
| Method | Endpoint | Description |
| :---: | :--- | :--- |
| <kbd>POST</kbd> | `/api/tasks` | Submit a new multi-step task to the LangGraph orchestrator. |
| <kbd>GET</kbd> | `/api/agents` | Retrieve the status and identity of all active agents. |
| <kbd>POST</kbd> | `/api/agents/{agent_id}/pause` | Manually suspend an agent from participating in the swarm. |

### 🛡️ Security & Trust
| Method | Endpoint | Description |
| :---: | :--- | :--- |
| <kbd>GET</kbd> | `/api/security/events` | Stream real-time security events (WebSocket available). |
| <kbd>GET</kbd> | `/api/trust/graph` | Export the current Neo4j trust mappings for visualization. |
| <kbd>POST</kbd> | `/api/healing/rollback/{agent_id}`| Force restore an agent's memory to its last clean snapshot. |

### 🛠️ Configuration & Simulation
| Method | Endpoint | Description |
| :---: | :--- | :--- |
| <kbd>POST</kbd> | `/api/settings/llm` | Hot-swap the underlying LLM provider (Azure/OpenAI/LMStudio). |
| <kbd>POST</kbd> | `/api/simulator/attack/{scenario}` | Launch a simulated attack (e.g. `PROMPT_INJECTION_BASIC`). |
| <kbd>GET</kbd> | `/api/health` | Service health check. |

---

## 🔒 Git Hooks & Security Compliance

This project ships with a strict, self-contained CI/CD and pre-commit pipeline.

By running `./setup_git_hooks.ps1` (or installing via `pre-commit install`), the following validations are run **before** every commit:
- 🚫 **Secret Masking:** Automatically detects and blocks API keys or passwords.
- 🧹 **Code Formatting:** Enforces `black` (100-chars) and `flake8` compliance.
- ⚡ **Syntax Checking:** Compiles all `.ts`/`.tsx` via Babel and checks Python ASTs.
- 📦 **Lockfile Verification:** Prevents dependency drift.

---

<div align="center">
  <i>Built with ❤️ for resilient and secure autonomous systems.</i>
</div>
