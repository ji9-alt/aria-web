# ARIA Web — Windows WebServer Install Script
# Run this on the WebServer VM (10.0.1.100) as Administrator
# Prerequisites: Python 3.12+ installed and in PATH

$ErrorActionPreference = "Stop"
$ARIA_DIR = "C:\ARIA"

Write-Host "`n[ARIA] Starting installation...`n" -ForegroundColor Green

# 1. Create directory structure
Write-Host "[1/7] Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\incoming" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\cache" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\tools" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\openclaw-rules" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\capa-rules" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA_DIR\capa-sigs" | Out-Null

# 2. Copy project files (assumes script is run from the repo directory)
Write-Host "[2/7] Copying project files..." -ForegroundColor Cyan
Copy-Item "api.py" "$ARIA_DIR\" -Force
Copy-Item "aria-lab.html" "$ARIA_DIR\" -Force
Copy-Item "openclaw_test.html" "$ARIA_DIR\" -Force
Copy-Item "openclaw-rules\*" "$ARIA_DIR\openclaw-rules\" -Recurse -Force
Copy-Item "capa-rules\*" "$ARIA_DIR\capa-rules\" -Recurse -Force

# 3. Install Python dependencies
Write-Host "[3/7] Installing Python dependencies..." -ForegroundColor Cyan
pip install flask pefile python-magic-bin ppdeep requests openai yara-python reportlab waitress psycopg2-binary 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  pip install failed, trying with --user..." -ForegroundColor Yellow
    pip install --user flask pefile python-magic-bin ppdeep requests openai yara-python reportlab waitress psycopg2-binary
}
Write-Host "  Done." -ForegroundColor Green

# 4. Download analysis tools
Write-Host "[4/7] Downloading analysis tools..." -ForegroundColor Cyan

$tools = @{
    "capa.exe"  = "https://github.com/mandiant/capa/releases/download/v9.3.1/capa-v9.3.1-windows.exe"
    "floss.exe" = "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.exe"
    "upx.exe"   = "https://github.com/upx/upx/releases/download/v5.0.1/upx-5.0.1-win64.zip"
}

foreach ($tool in $tools.Keys) {
    $url = $tools[$tool]
    $dest = "$ARIA_DIR\tools\$tool"
    if (Test-Path $dest) {
        Write-Host "  $tool already exists, skipping." -ForegroundColor Gray
        continue
    }
    Write-Host "  Downloading $tool..." -ForegroundColor Gray
    try {
        if ($url -like "*.zip") {
            $zipPath = "$env:TEMP\$tool.zip"
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\$tool-extract" -Force
            $exe = Get-ChildItem "$env:TEMP\$tool-extract" -Recurse -Filter "*.exe" | Select-Object -First 1
            Copy-Item $exe.FullName $dest
            Remove-Item $zipPath -Force
            Remove-Item "$env:TEMP\$tool-extract" -Recurse -Force
        } else {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        }
        Write-Host "  $tool OK" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED to download $tool : $_" -ForegroundColor Red
    }
}

# Download Sysinternals strings.exe (Windows has no built-in strings)
if (-not (Test-Path "$ARIA_DIR\tools\strings.exe")) {
    Write-Host "  Downloading strings.exe (Sysinternals)..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri "https://live.sysinternals.com/strings.exe" -OutFile "$ARIA_DIR\tools\strings.exe" -UseBasicParsing
        Write-Host "  strings.exe OK" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED to download strings.exe" -ForegroundColor Red
    }
}

# Download YARA
if (-not (Test-Path "$ARIA_DIR\tools\yara64.exe")) {
    Write-Host "  Downloading yara64.exe..." -ForegroundColor Gray
    try {
        $yaraZip = "$env:TEMP\yara.zip"
        Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -OutFile $yaraZip -UseBasicParsing
        Expand-Archive -Path $yaraZip -DestinationPath "$env:TEMP\yara-extract" -Force
        Copy-Item "$env:TEMP\yara-extract\yara64.exe" "$ARIA_DIR\tools\yara64.exe" -Force
        Remove-Item $yaraZip -Force
        Remove-Item "$env:TEMP\yara-extract" -Recurse -Force
        Write-Host "  yara64.exe OK" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED to download yara: $_" -ForegroundColor Red
    }
}

# Download capa-sigs
if (-not (Test-Path "$ARIA_DIR\capa-sigs\sigs")) {
    Write-Host "  Downloading CAPA signatures..." -ForegroundColor Gray
    try {
        $sigZip = "$env:TEMP\capa-sigs.zip"
        Invoke-WebRequest -Uri "https://github.com/mandiant/capa/releases/download/v9.3.1/capa-v9.3.1-signatures.zip" -OutFile $sigZip -UseBasicParsing
        Expand-Archive -Path $sigZip -DestinationPath "$ARIA_DIR\capa-sigs" -Force
        Write-Host "  capa-sigs OK" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
    }
}

# 5. Add tools to PATH for this session
Write-Host "[5/7] Configuring PATH..." -ForegroundColor Cyan
$env:PATH = "$ARIA_DIR\tools;$env:PATH"
[Environment]::SetEnvironmentVariable("PATH", "$ARIA_DIR\tools;" + [Environment]::GetEnvironmentVariable("PATH", "Machine"), "Machine")

# 6. Generate self-signed TLS certificate
Write-Host "[6/7] Generating TLS certificate..." -ForegroundColor Cyan
if (-not (Test-Path "$ARIA_DIR\cert.pem")) {
    # Try openssl first
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
    if ($opensslPath) {
        openssl req -x509 -newkey rsa:2048 -keyout "$ARIA_DIR\key.pem" -out "$ARIA_DIR\cert.pem" -days 365 -nodes -subj "/CN=aria.local" 2>&1 | Out-Null
        Write-Host "  TLS cert generated with OpenSSL" -ForegroundColor Green
    } else {
        # Fallback: use Python
        python -c @"
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'aria.local')])
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
with open(r'C:\ARIA\key.pem','wb') as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open(r'C:\ARIA\cert.pem','wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
"@
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  TLS cert generated with Python" -ForegroundColor Green
        } else {
            Write-Host "  WARNING: Could not generate TLS cert. Install pyOpenSSL: pip install cryptography" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  TLS cert already exists" -ForegroundColor Gray
}

# 7. Summary
Write-Host "`n[7/7] Installation complete!" -ForegroundColor Green
Write-Host @"

  ARIA Web is ready at: C:\ARIA\

  To start ARIA:
    cd C:\ARIA
    python api.py

  Then browse to: https://10.0.1.100:5000/

  API Keys (set as environment variables or edit api.py):
    VT_API_KEY         - VirusTotal
    OPENROUTER_API_KEY - AI Analysis (fallback key is hardcoded)
    ABUSEIPDB_API_KEY  - IP reputation

"@ -ForegroundColor Cyan
