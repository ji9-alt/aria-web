$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ARIA = "C:\ARIA"

Write-Host ""
Write-Host "  ARIA Web - Full Setup" -ForegroundColor Green
Write-Host ""

# 1. Directories
Write-Host "[1/5] Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$ARIA\incoming" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA\cache" | Out-Null
New-Item -ItemType Directory -Force -Path "$ARIA\tools" | Out-Null
Write-Host "  Done."

# 2. Python packages
Write-Host "[2/5] Installing Python packages..." -ForegroundColor Cyan
python -m pip install --upgrade pip 2>$null
pip install flask pefile python-magic-bin ppdeep requests openai yara-python reportlab waitress
Write-Host "  Done."

# 3. Download tools
Write-Host "[3/5] Downloading analysis tools..." -ForegroundColor Cyan

if (-not (Test-Path "$ARIA\tools\capa.exe")) {
    Write-Host "  Downloading capa..."
    try {
        Invoke-WebRequest -Uri "https://github.com/mandiant/capa/releases/download/v9.3.1/capa-v9.3.1-windows.exe" -OutFile "$ARIA\tools\capa.exe" -UseBasicParsing
        Write-Host "  capa OK"
    } catch {
        Write-Host "  capa FAILED" -ForegroundColor Red
    }
}

if (-not (Test-Path "$ARIA\tools\floss.exe")) {
    Write-Host "  Downloading floss..."
    try {
        Invoke-WebRequest -Uri "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.exe" -OutFile "$ARIA\tools\floss.exe" -UseBasicParsing
        Write-Host "  floss OK"
    } catch {
        Write-Host "  floss FAILED" -ForegroundColor Red
    }
}

if (-not (Test-Path "$ARIA\tools\strings.exe")) {
    Write-Host "  Downloading strings..."
    try {
        Invoke-WebRequest -Uri "https://live.sysinternals.com/strings.exe" -OutFile "$ARIA\tools\strings.exe" -UseBasicParsing
        Write-Host "  strings OK"
    } catch {
        Write-Host "  strings FAILED" -ForegroundColor Red
    }
}

if (-not (Test-Path "$ARIA\tools\upx.exe")) {
    Write-Host "  Downloading upx..."
    try {
        $zip = "$env:TEMP\upx.zip"
        Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v5.0.1/upx-5.0.1-win64.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath "$env:TEMP\upx-extract" -Force
        $found = Get-ChildItem "$env:TEMP\upx-extract" -Recurse -Filter "upx.exe" | Select-Object -First 1
        if ($found) { Copy-Item $found.FullName "$ARIA\tools\upx.exe" -Force }
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\upx-extract" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  upx OK"
    } catch {
        Write-Host "  upx FAILED" -ForegroundColor Red
    }
}

if (-not (Test-Path "$ARIA\tools\yara64.exe")) {
    Write-Host "  Downloading yara..."
    try {
        $zip = "$env:TEMP\yara.zip"
        Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath "$env:TEMP\yara-extract" -Force
        $found = Get-ChildItem "$env:TEMP\yara-extract" -Recurse -Filter "yara64.exe" | Select-Object -First 1
        if ($found) { Copy-Item $found.FullName "$ARIA\tools\yara64.exe" -Force }
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\yara-extract" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  yara OK"
    } catch {
        Write-Host "  yara FAILED" -ForegroundColor Red
    }
}

# Add tools to PATH
$env:PATH = "$ARIA\tools;" + $env:PATH
[Environment]::SetEnvironmentVariable("PATH", "$ARIA\tools;" + [Environment]::GetEnvironmentVariable("PATH", "Machine"), "Machine")
Write-Host "  Tools added to PATH"

# 4. Windows Firewall
Write-Host "[4/5] Opening firewall ports..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "ARIA Web 5000" -Direction Inbound -Port 5000 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "ARIA Web 443" -Direction Inbound -Port 443 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "  Ports 443 and 5000 open."

# 5. Done
Write-Host "[5/5] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  To start:  cd C:\ARIA && python api.py"
Write-Host "  Web UI:    http://10.0.1.100:5000/test"
Write-Host ""
