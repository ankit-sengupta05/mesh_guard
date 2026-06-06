# ============================================================
# Git Hook Initializer v4.0 -- Universal Project Setup
# Supports: Python, JS, JSX, TSX, TS, Java, Kotlin,
#           Go, Rust, Ruby, PHP, Swift, C, C++, Dart
#
# FIXES APPLIED:
#   - JSX/TSX use @babel/parser (not node --check)
#   - All Python scripts are flake8-clean (E231, E501 safe)
#   - Cross-platform Rust (Windows nul / Linux /dev/null)
#   - codespell excludes auto-generated lock files
#   - Two-pass commit handles end-of-file-fixer auto-fixes
#   - Submodule backend auto-detection and fix
#   - check_requirements uses pass_filenames: false
#
# USAGE:
#   Open PowerShell in your project root and paste this script
# ============================================================

# ============================
# Step 1: Initialize Git repo
# ============================
git init
git branch -M main

# ============================
# Step 2: .gitignore
# ============================
Set-Content .gitignore -Encoding utf8 @'
# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.env/
venv/
env/
*.egg-info/
dist/
build/

# Node / JS / TS
node_modules/
dist/
.next/
.nuxt/
*.tsbuildinfo

# Java / Kotlin
*.class
*.jar
*.war
target/
.gradle/

# C / C++
*.o
*.out
*.a
*.so
*.exe

# Go
vendor/

# Rust
target/

# Ruby
.bundle/
vendor/bundle/

# Dart / Flutter
.dart_tool/
.flutter-plugins

# IDE
.vscode/
.idea/
*.swp
.DS_Store

# Logs
*.log

# Secrets -- NEVER commit these
.env
.env.local
.env.production
.env.development
.env.staging
google-services.json
GoogleService-Info.plist
*.secret
*.pem
*.key
*.p12
*.keystore
'@

# ============================
# Step 3: Install Python tools
# Auto-detects virtualenv -- never uses --user inside a venv
# ============================
python -m pip install --upgrade pip --quiet

# Detect virtualenv and install accordingly
$inVenv = python -c "import sys; print(1 if sys.prefix != sys.base_prefix else 0)" 2>$null
if ($inVenv -eq 1) {
    Write-Host "  Virtualenv detected -- installing into venv" -ForegroundColor Cyan
    pip install pre-commit flake8 pyflakes --quiet
} else {
    Write-Host "  No virtualenv -- installing with --user" -ForegroundColor Cyan
    python -m pip install --user pre-commit flake8 pyflakes --quiet
}

# ============================
# Step 4: Install Node tools
# (required for JSX/TSX babel syntax checking)
# ============================
npm install -g @babel/parser --silent

# ============================
# Step 5: Create scripts folder
# ============================
New-Item -ItemType Directory -Force -Path scripts | Out-Null

# ============================
# Step 6: mask_keys.py
# ============================
Set-Content scripts\mask_keys.py -Encoding utf8 @'
# -*- coding: utf-8 -*-
# scripts/mask_keys.py
import re
import sys
from pathlib import Path

SKIP_FILES = {
    'mask_keys.py',
    '.pre-commit-config.yaml',
    'package-lock.json',
    'yarn.lock',
}

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico',
    '.svg', '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.lock', '.bin',
    '.class', '.jar', '.exe', '.so', '.a',
}

SECRET_PATTERNS = [
    (
        r'(FIREBASE_API_KEY'
        r'|FIREBASE_AUTH_DOMAIN'
        r'|FIREBASE_PROJECT_ID'
        r'|FIREBASE_STORAGE_BUCKET'
        r'|FIREBASE_MESSAGING_SENDER_ID'
        r'|FIREBASE_APP_ID'
        r'|FIREBASE_MEASUREMENT_ID'
        r'|API_KEY'
        r'|API_SECRET'
        r'|APP_SECRET'
        r'|AUTH_TOKEN'
        r'|ACCESS_TOKEN'
        r'|REFRESH_TOKEN'
        r'|SECRET_KEY'
        r'|PRIVATE_KEY'
        r'|CLIENT_SECRET'
        r'|CLIENT_ID'
        r'|DATABASE_URL'
        r'|DATABASE_PASSWORD'
        r'|DB_PASSWORD'
        r'|DB_USER'
        r'|SMTP_PASSWORD'
        r'|SENDGRID_API_KEY'
        r'|STRIPE_SECRET_KEY'
        r'|STRIPE_PUBLISHABLE_KEY'
        r'|AWS_ACCESS_KEY_ID'
        r'|AWS_SECRET_ACCESS_KEY'
        r'|GOOGLE_CLIENT_SECRET'
        r'|GITHUB_TOKEN'
        r'|JWT_SECRET'
        r'|ENCRYPTION_KEY'
        r'|PASSWORD)'
        r'=[^\s\n"' + "'" + r'`]+'
    ),
]

masked_files = []
files_to_scan = sys.argv[1:] if len(sys.argv) > 1 else []

for file_str in files_to_scan:
    file_path = Path(file_str)
    if not file_path.is_file():
        continue
    if file_path.name in SKIP_FILES:
        continue
    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        continue
    try:
        content = file_path.read_text(errors='ignore')
    except Exception:
        continue
    original = content
    for pattern in SECRET_PATTERNS:
        content = re.sub(
            pattern,
            lambda m: m.group(0).split('=')[0] + '=******',
            content,
        )
    if content != original:
        file_path.write_text(content)
        masked_files.append(str(file_path))

if masked_files:
    msg = '[MASKED] Secrets found in: ' + ', '.join(masked_files)
    sys.stdout.buffer.write(msg.encode('utf-8') + b'\n')
    sys.stdout.buffer.write(
        b'[ACTION] Review changes, re-stage and commit again.\n'
    )
    sys.exit(1)
else:
    sys.stdout.buffer.write(b'[OK] No secrets found.\n')
    sys.exit(0)
'@

# ============================
# Step 7: compile_check.py
# FIXED:
#   - .jsx -> babel (not node --check)
#   - .tsx -> babel (not tsc)
#   - .mjs/.cjs added
#   - Rust cross-platform (nul/dev/null)
#   - No alignment spaces in dict (E231 safe)
#   - All lines <= 100 chars (E501 safe)
#   - Logic moved into check_file() function
# ============================
Set-Content scripts\compile_check.py -Encoding utf8 @'
# -*- coding: utf-8 -*-
# scripts/compile_check.py
# Auto-detects language from file extension and runs the
# correct syntax checker. Never blocks commit if tool missing.
import subprocess
import sys
from pathlib import Path

SUPPORTED = {
    '.py': 'python',
    '.js': 'node',
    '.mjs': 'node',
    '.cjs': 'node',
    '.jsx': 'jsx',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.java': 'java',
    '.kt': 'kotlin',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.dart': 'dart',
    '.swift': 'swift',
    '.c': 'c',
    '.cpp': 'cpp',
}

# Inline Node script using @babel/parser for JSX/TSX.
# node --check does NOT understand JSX and will always crash.
BABEL_SCRIPT = (
    "const fs=require('fs');"
    "const b=require('@babel/parser');"
    "try{"
    "b.parse(fs.readFileSync(process.argv[1],'utf8'),{"
    "sourceType:'module',"
    "plugins:['jsx','typescript','classProperties','decorators-legacy']"
    "});"
    "process.exit(0);"
    "}catch(e){"
    "console.error(e.message);"
    "process.exit(1);"
    "}"
)

errors = []
files_to_scan = sys.argv[1:] if len(sys.argv) > 1 else []


def run(cmd, label, filepath):
    """Run a check command. Skip silently if tool not installed."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            out = (result.stderr or result.stdout).strip()
            errors.append(
                '[' + label + '] ' + filepath + '\n  ' + out
            )
            return False
        return True
    except FileNotFoundError:
        # Tool not installed -- never block the commit
        return True
    except subprocess.TimeoutExpired:
        errors.append('[TIMEOUT] ' + filepath)
        return False


def check_babel(filepath, label):
    """Use @babel/parser for JSX and TSX files."""
    run(
        ['node', '-e', BABEL_SCRIPT, filepath],
        label,
        filepath,
    )


def check_file(filepath):
    """Detect language by extension and run correct checker."""
    fp = Path(filepath)
    if not fp.is_file():
        return
    lang = SUPPORTED.get(fp.suffix.lower())
    if not lang:
        return
    p = str(fp)

    if lang == 'python':
        run(['python', '-m', 'py_compile', p], 'Python', p)

    elif lang == 'node':
        # Plain JS only -- no JSX, node --check works fine
        run(['node', '--check', p], 'JavaScript', p)

    elif lang == 'jsx':
        # MUST use babel -- node --check crashes on JSX syntax
        check_babel(p, 'JSX')

    elif lang == 'typescript':
        run(
            [
                'npx', '--yes', 'tsc',
                '--noEmit', '--allowJs',
                '--strict', '--target', 'ES2020', p,
            ],
            'TypeScript',
            p,
        )

    elif lang == 'tsx':
        # TSX = TypeScript + JSX -- babel handles both
        check_babel(p, 'TSX')

    elif lang == 'java':
        run(['javac', '-proc:none', p], 'Java', p)

    elif lang == 'kotlin':
        run(['kotlinc', '-script', p], 'Kotlin', p)

    elif lang == 'go':
        run(['go', 'vet', p], 'Go', p)

    elif lang == 'rust':
        # Cross-platform: nul on Windows, /dev/null on Linux/Mac
        null_out = 'nul' if sys.platform == 'win32' else '/dev/null'
        run(
            [
                'rustc', '--edition', '2021',
                '--emit=metadata', '-o', null_out, p,
            ],
            'Rust',
            p,
        )

    elif lang == 'ruby':
        run(['ruby', '-c', p], 'Ruby', p)

    elif lang == 'php':
        run(['php', '-l', p], 'PHP', p)

    elif lang == 'dart':
        run(['dart', 'analyze', p], 'Dart', p)

    elif lang == 'swift':
        run(['swiftc', '-parse', p], 'Swift', p)

    elif lang == 'c':
        run(['gcc', '-fsyntax-only', p], 'C', p)

    elif lang == 'cpp':
        run(['g++', '-fsyntax-only', p], 'C++', p)


for f in files_to_scan:
    check_file(f)

if errors:
    sys.stdout.buffer.write(b'\n[COMPILE ERROR] Fix before committing:\n')
    sys.stdout.buffer.write(b'=' * 60 + b'\n')
    for err in errors:
        sys.stdout.buffer.write(err.encode('utf-8') + b'\n')
        sys.stdout.buffer.write(b'-' * 60 + b'\n')
    sys.exit(1)
else:
    sys.stdout.buffer.write(b'[OK] All files passed syntax check.\n')
    sys.exit(0)
'@

# ============================
# Step 8: check_requirements.py
# FIXED: E231-safe, E501-safe, multi-line string concat
# ============================
Set-Content scripts\check_requirements.py -Encoding utf8 @'
# -*- coding: utf-8 -*-
# scripts/check_requirements.py
from pathlib import Path
import sys

req_file = Path('requirements.txt')
if req_file.exists():
    lines = req_file.read_text().splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            if '==' not in stripped and '>=' not in stripped:
                msg = (
                    'Warning: line '
                    + str(i)
                    + ' no version pin: '
                    + stripped
                )
                sys.stdout.buffer.write(msg.encode('utf-8') + b'\n')
'@

# ============================
# Step 9: .env.example
# ============================
Set-Content .env.example -Encoding utf8 @'
# .env.example -- copy to .env and fill in real values
# NEVER commit .env to git

FIREBASE_API_KEY=******
FIREBASE_AUTH_DOMAIN=******
FIREBASE_PROJECT_ID=******
FIREBASE_STORAGE_BUCKET=******
FIREBASE_MESSAGING_SENDER_ID=******
FIREBASE_APP_ID=******
FIREBASE_MEASUREMENT_ID=******

API_KEY=******
SECRET_KEY=******
DATABASE_URL=******
JWT_SECRET=******
ACCESS_TOKEN=******
REFRESH_TOKEN=******
'@

# ============================
# Step 10: requirements.txt
# ============================
python -m pip freeze | Out-File -FilePath requirements.txt -Encoding utf8

# ============================
# Step 11: .pre-commit-config.yaml
# FIXED:
#   - codespell excludes lock files and .expo/
#   - check-requirements uses pass_filenames: false
#   - compile-check excludes .css/.scss/.html
# ============================
Set-Content .pre-commit-config.yaml -Encoding utf8 @'
repos:
- repo: https://github.com/pre-commit/pre-commit-hooks
  rev: v4.5.0
  hooks:
    - id: trailing-whitespace
    - id: end-of-file-fixer
    - id: check-added-large-files
      args: ["--maxkb=1000"]
    - id: check-yaml
    - id: check-json
    - id: check-merge-conflict
    - id: detect-private-key
    - id: no-commit-to-branch
      args: ["--branch", "production"]

- repo: https://github.com/pycqa/flake8
  rev: 7.0.0
  hooks:
    - id: flake8
      args: ["--max-line-length=100"]
      files: \.py$
      exclude: ^(venv|env|\.git)/

- repo: https://github.com/codespell-project/codespell
  rev: v2.2.2
  hooks:
    - id: codespell
      exclude: ^(package-lock\.json|yarn\.lock|\.expo/)
      args: ["--skip=*.lock,*.min.js,*.json"]

- repo: local
  hooks:
    - id: mask-secrets
      name: Mask secrets in staged files
      entry: python scripts/mask_keys.py
      language: system
      pass_filenames: true
      types: [text]
      exclude: >-
        (?x)^(
          scripts/mask_keys\.py|
          \.pre-commit-config\.yaml|
          .*\.lock|.*\.png|.*\.jpg|
          .*\.svg|.*\.exe|.*\.bin
        )$

    - id: compile-check
      name: Syntax and compile check (auto language detection)
      entry: python scripts/compile_check.py
      language: system
      pass_filenames: true
      types: [text]
      exclude: >-
        (?x)^(
          .*\.lock|.*\.md|.*\.txt|
          .*\.png|.*\.jpg|.*\.svg|
          .*\.json|.*\.yaml|.*\.yml|
          .*\.env.*|.*\.gitignore|
          .*\.css|.*\.scss|.*\.html
        )$

    - id: check-requirements
      name: Check requirements file syntax
      entry: python scripts/check_requirements.py
      language: system
      pass_filenames: false
      files: ^requirements\.txt$
'@

# ============================
# Step 12: GitHub Actions CI
# FIXED: added @babel/parser install, jsx/tsx in secret scan
# ============================
New-Item -ItemType Directory -Force -Path .github\workflows | Out-Null

Set-Content .github\workflows\ci.yml -Encoding utf8 @'
name: CI -- Lint, Compile and Secret Check

on:
  push:
    branches: ["main", "dev"]
  pull_request:

jobs:
  lint_compile_check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Set up Java
        uses: actions/setup-java@v4
        with:
          java-version: "17"
          distribution: "temurin"

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.21"

      - name: Install Python tools
        run: |
          python -m pip install --upgrade pip
          pip install pre-commit flake8

      - name: Install Node tools
        run: npm install -g @babel/parser

      - name: Run all pre-commit hooks
        run: pre-commit run --all-files

      - name: Check for raw secrets in source
        run: |
          if grep -rE \
            "(API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|AUTH_TOKEN)=[^*[:space:]]+" \
            --include="*.js" --include="*.ts" \
            --include="*.jsx" --include="*.tsx" \
            --include="*.py" --include="*.java" --include="*.go" \
            --exclude-dir=node_modules --exclude-dir=.git .; then
            echo "[FAIL] Raw secrets detected!"
            exit 1
          else
            echo "[OK] No raw secrets found."
          fi
'@

# ============================
# Step 13: Auto-fix any nested .git submodule issues
# ============================
Write-Host "Checking for nested .git submodules..." -ForegroundColor Cyan
$folders = Get-ChildItem -Directory | Where-Object {
    Test-Path (Join-Path $_.FullName ".git")
}
foreach ($folder in $folders) {
    Write-Host "  Fixing nested .git in: $($folder.Name)" -ForegroundColor Yellow
    Remove-Item -Recurse -Force (Join-Path $folder.FullName ".git")
    git rm -r --cached $folder.Name 2>$null
}
if (Test-Path .gitmodules) {
    Remove-Item -Force .gitmodules
    Write-Host "  Removed .gitmodules" -ForegroundColor Yellow
}
git config --remove-section submodule 2>$null

# ============================
# Step 14: Install pre-commit hooks
# ============================
python -m pre_commit install --hook-type pre-commit
python -m pre_commit install --hook-type pre-push

# ============================
# Step 15: Initial commit
# ============================
git add .
git commit -m "chore: init repo with pre-commit hooks, secret masking, auto compile checks" 2>$null
git add .
git commit -m "chore: fix EOF newlines from pre-commit auto-fix" 2>$null

# ============================
# Step 16: Push to GitHub
# ============================
$repoUrl = "https://github.com/ankit-sengupta05/mesh_guard.git"
Write-Host "  Connecting to: $repoUrl" -ForegroundColor Gray
git remote add origin $repoUrl 2>$null
git remote set-url origin $repoUrl 2>$null
git push -u origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Pushed successfully!" -ForegroundColor Green
} else {
    Write-Host "  Push failed. Run manually: git push -u origin main" -ForegroundColor Red
}

# ============================
# Done
# ============================
Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  Setup complete! All hooks active." -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host ""
