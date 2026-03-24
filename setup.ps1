# ARIA Web — Full Setup Script
# Run from C:\ARIA after git clone
# Usage: powershell -ExecutionPolicy Bypass -File setup.ps1

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ARIA = "C:\ARIA"
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  ARIA Web — Full Setup" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# ─── 1. Directories ───
Write-Host "[1/6] Creating directories..." -ForegroundColor Cyan
@("incoming", "cache", "tools") | ForEach-Object {
    New-Item -ItemType Directory -Force -Path "$ARIA\$_" | Out-Null
}
Write-Host "  Done.`n" -ForegroundColor Green

# ─── 2. Python dependencies ───
Write-Host "[2/6] Installing Python packages..." -ForegroundColor Cyan
python -m pip install --upgrade pip 2>$null
pip install flask pefile python-magic-bin ppdeep requests openai yara-python reportlab waitress
Write-Host "  Done.`n" -ForegroundColor Green

# ─── 3. Download analysis tools ───
Write-Host "[3/6] Downloading analysis tools..." -ForegroundColor Cyan

function Download-Tool($name, $url, $dest) {
    if (Test-Path $dest) {
        Write-Host "  $name — already exists" -ForegroundColor Gray
        return
    }
    Write-Host "  $name — downloading..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        Write-Host "  $name — OK" -ForegroundColor Green
    } catch {
        Write-Host "  $name — FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Download-Zip($name, $url, $exeName, $dest) {
    if (Test-Path $dest) {
        Write-Host "  $name — already exists" -ForegroundColor Gray
        return
    }
    Write-Host "  $name — downloading..." -ForegroundColor Yellow
    try {
        $zip = "$env:TEMP\$name.zip"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $extractDir = "$env:TEMP\$name-extract"
        Expand-Archive -Path $zip -DestinationPath $extractDir -Force
        $exe = Get-ChildItem $extractDir -Recurse -Filter $exeName | Select-Object -First 1
        if ($exe) {
            Copy-Item $exe.FullName $dest -Force
            Write-Host "  $name — OK" -ForegroundColor Green
        } else {
            Write-Host "  $name — exe not found in zip" -ForegroundColor Red
        }
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  $name — FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# CAPA
Download-Tool "capa" "https://github.com/mandiant/capa/releases/download/v9.3.1/capa-v9.3.1-windows.exe" "$ARIA\tools\capa.exe"

# FLOSS
Download-Tool "floss" "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.exe" "$ARIA\tools\floss.exe"

# Sysinternals strings
Download-Tool "strings" "https://live.sysinternals.com/strings.exe" "$ARIA\tools\strings.exe"

# UPX (zip)
Download-Zip "upx" "https://github.com/upx/upx/releases/download/v5.0.1/upx-5.0.1-win64.zip" "upx.exe" "$ARIA\tools\upx.exe"

# YARA (zip)
Download-Zip "yara" "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" "yara64.exe" "$ARIA\tools\yara64.exe"

# Add tools to PATH
$env:PATH = "$ARIA\tools;$env:PATH"
[Environment]::SetEnvironmentVariable("PATH", "$ARIA\tools;" + [Environment]::GetEnvironmentVariable("PATH", "Machine"), "Machine")
Write-Host "  Tools added to PATH`n" -ForegroundColor Green

# ─── 4. Generate TLS certificate ───
Write-Host "[4/6] Generating TLS certificate..." -ForegroundColor Cyan
if (-not (Test-Path "$ARIA\cert.pem")) {
    try {
        # Use PowerShell to generate self-signed cert and export to PEM
        $cert = New-SelfSignedCertificate -DnsName "aria.local","10.0.1.100" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(2)

        # Export cert as PEM using certutil
        Export-Certificate -Cert $cert -FilePath "$ARIA\cert.der" -Type CERT | Out-Null
        certutil -encode "$ARIA\cert.der" "$ARIA\cert.pem" | Out-Null
        Remove-Item "$ARIA\cert.der" -Force -ErrorAction SilentlyContinue

        # Export private key — use pfx then convert
        $pwd = ConvertTo-SecureString -String "temp123" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath "$ARIA\cert.pfx" -Password $pwd | Out-Null
        certutil -exportPFX -p "temp123" "$ARIA\cert.pfx" "$ARIA\key.pem" | Out-Null

        # If certutil PEM export didn't work, try openssl
        if (-not (Test-Path "$ARIA\key.pem") -or (Get-Item "$ARIA\key.pem").Length -lt 100) {
            # Fallback: just run without TLS
            Write-Host "  TLS key export tricky on Windows Server — will run HTTP" -ForegroundColor Yellow
            Remove-Item "$ARIA\cert.pem" -Force -ErrorAction SilentlyContinue
            Remove-Item "$ARIA\key.pem" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  TLS cert generated" -ForegroundColor Green
        }
        Remove-Item "$ARIA\cert.pfx" -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  TLS generation failed — will run HTTP on port 5000" -ForegroundColor Yellow
    }
} else {
    Write-Host "  TLS cert already exists" -ForegroundColor Green
}
Write-Host ""

# ─── 5. Windows Firewall ───
Write-Host "[5/6] Opening Windows Firewall port..." -ForegroundColor Cyan
# Allow inbound on 5000 and 443
New-NetFirewallRule -DisplayName "ARIA Web 5000" -Direction Inbound -Port 5000 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "ARIA Web 443" -Direction Inbound -Port 443 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "  Firewall rules added (ports 443, 5000)`n" -ForegroundColor Green

# ─── 6. Done ───
Write-Host "[6/6] Setup complete!" -ForegroundColor Green
Write-Host @"

  ========================================
  ARIA is ready!
  ========================================

  To start:    cd C:\ARIA && python api.py

  Web UI:      http://10.0.1.100:5000/test
               http://10.0.1.100:5000/

  Tools in:    C:\ARIA\tools\
  Uploads in:  C:\ARIA\incoming\
  Cache in:    C:\ARIA\cache\

  ========================================

"@ -ForegroundColor Cyan
