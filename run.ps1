# ===========================================================================
# AgentOps Security Mesh — PowerShell Task Runner (Windows replacement for make)
# Usage: .\run.ps1 <target>
# Example: .\run.ps1 stack-up
# ===========================================================================

param(
    [Parameter(Position=0)]
    [string]$Target = "help"
)

$ProjectRoot = $PSScriptRoot
$BackendDir  = Join-Path $ProjectRoot "backend"
$FrontendDir = Join-Path $ProjectRoot "frontend"
$ScriptsDir  = Join-Path $ProjectRoot "scripts"

function Show-Help {
    Write-Host ""
    Write-Host "  AgentOps Security Mesh — Windows Task Runner" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  .\run.ps1 install        Install all Python + Node dependencies"
    Write-Host "  .\run.ps1 infra-up       Start Redis + Neo4j via Docker"
    Write-Host "  .\run.ps1 backend        Start FastAPI backend"
    Write-Host "  .\run.ps1 frontend       Start React dev server"
    Write-Host "  .\run.ps1 stack-up       Build + start full Docker stack"
    Write-Host "  .\run.ps1 stack-down     Stop full Docker stack"
    Write-Host "  .\run.ps1 test           Run integration tests"
    Write-Host "  .\run.ps1 attack-demo    Run the hackathon attack demo"
    Write-Host "  .\run.ps1 load-test      Run stress test"
    Write-Host "  .\run.ps1 clean          Stop Docker and remove volumes"
    Write-Host ""
}

function Invoke-Install {
    Write-Host "→ Installing backend dependencies..." -ForegroundColor Yellow
    Push-Location $BackendDir
    pip install -r requirements.txt
    Pop-Location

    Write-Host "→ Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location $FrontendDir
    npm install
    Pop-Location

    if (-not (Test-Path (Join-Path $ProjectRoot ".env"))) {
        Write-Host "→ Copying .env.example to .env..." -ForegroundColor Yellow
        Copy-Item (Join-Path $ProjectRoot ".env.example") (Join-Path $ProjectRoot ".env")
        Write-Host "  ✓ .env created. Edit it and add your AZURE_OPENAI_API_KEY." -ForegroundColor Green
    }
}

function Invoke-InfraUp {
    Write-Host "→ Starting Redis and Neo4j..." -ForegroundColor Yellow
    docker-compose up -d redis neo4j
    Write-Host "→ Waiting for Redis..." -ForegroundColor DarkGray
    $retries = 0
    while ($retries -lt 15) {
        $result = docker exec agentops-redis redis-cli ping 2>$null
        if ($result -eq "PONG") { Write-Host "  ✓ Redis ready." -ForegroundColor Green; break }
        Start-Sleep 2; $retries++
    }
    Write-Host "  ✓ Neo4j starting (takes ~30s on first boot)..." -ForegroundColor DarkGray
}

function Invoke-Backend {
    Write-Host "→ Starting FastAPI backend on http://localhost:8000 ..." -ForegroundColor Yellow
    Push-Location $BackendDir
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
    Pop-Location
}

function Invoke-Frontend {
    Write-Host "→ Starting React dashboard on http://localhost:5173 ..." -ForegroundColor Yellow
    Push-Location $FrontendDir
    npm run dev
    Pop-Location
}

function Invoke-StackUp {
    Write-Host "→ Building and starting full Docker stack..." -ForegroundColor Yellow
    docker-compose up --build -d
    Write-Host ""
    Write-Host "  ✓ Stack started!" -ForegroundColor Green
    Write-Host "  Frontend  → http://localhost:5173" -ForegroundColor Cyan
    Write-Host "  Backend   → http://localhost:8000" -ForegroundColor Cyan
    Write-Host "  API Docs  → http://localhost:8000/docs" -ForegroundColor Cyan
    Write-Host "  Neo4j UI  → http://localhost:7474" -ForegroundColor Cyan
}

function Invoke-StackDown {
    Write-Host "→ Stopping Docker stack..." -ForegroundColor Yellow
    docker-compose down
}

function Invoke-Test {
    Write-Host "→ Running integration tests..." -ForegroundColor Yellow
    Push-Location $BackendDir
    python -m pytest tests/test_integration.py -v --asyncio-mode=auto
    Pop-Location
}

function Invoke-AttackDemo {
    Write-Host "→ Running hackathon demo against http://localhost:8000 ..." -ForegroundColor Yellow
    python (Join-Path $ScriptsDir "demo.py") --backend-url http://localhost:8000
}

function Invoke-LoadTest {
    Write-Host "→ Running load test against http://localhost:8000 ..." -ForegroundColor Yellow
    python (Join-Path $ScriptsDir "load_test.py") --backend-url http://localhost:8000
}

function Invoke-Clean {
    Write-Host "→ Stopping containers and removing volumes..." -ForegroundColor Yellow
    docker-compose down -v --remove-orphans
    Write-Host "  ✓ Clean." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
switch ($Target.ToLower()) {
    "help"         { Show-Help }
    "install"      { Invoke-Install }
    "infra-up"     { Invoke-InfraUp }
    "backend"      { Invoke-Backend }
    "frontend"     { Invoke-Frontend }
    "stack-up"     { Invoke-StackUp }
    "stack-down"   { Invoke-StackDown }
    "test"         { Invoke-Test }
    "attack-demo"  { Invoke-AttackDemo }
    "load-test"    { Invoke-LoadTest }
    "clean"        { Invoke-Clean }
    default {
        Write-Host "Unknown target: '$Target'. Run '.\run.ps1 help' for options." -ForegroundColor Red
        exit 1
    }
}
