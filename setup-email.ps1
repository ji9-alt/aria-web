# ARIA Email Server Setup - Windows Server 2025
# Installs hMailServer for internal email

Write-Host ""
Write-Host "  ARIA Email Server Setup" -ForegroundColor Red
Write-Host ""

$tempDir = "$env:TEMP\aria-email"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Step 1: Download hMailServer
Write-Host "[1/3] Downloading hMailServer..." -ForegroundColor Yellow
$hmsUrl = "https://www.hmailserver.com/files/hMailServer-5.6.9-B2688.exe"
$hmsPath = "$tempDir\hmailserver.exe"

try {
    Invoke-WebRequest -Uri $hmsUrl -OutFile $hmsPath -UseBasicParsing
    Write-Host "  Downloaded" -ForegroundColor Green
} catch {
    Write-Host "  Download failed. Download manually from:" -ForegroundColor Red
    Write-Host "  https://www.hmailserver.com/download" -ForegroundColor White
    Write-Host "  Then run the installer and come back to this script" -ForegroundColor Yellow
}

# Step 2: Install hMailServer silently
Write-Host "[2/3] Installing hMailServer..." -ForegroundColor Yellow
if (Test-Path $hmsPath) {
    Start-Process $hmsPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -NoNewWindow
    Write-Host "  hMailServer installed" -ForegroundColor Green
} else {
    Write-Host "  Installer not found, skipping..." -ForegroundColor Yellow
}

# Step 3: Firewall rules for email
Write-Host "[3/3] Configuring firewall for email..." -ForegroundColor Yellow
netsh advfirewall firewall add rule name="SMTP" dir=in action=allow protocol=tcp localport=25 2>$null
netsh advfirewall firewall add rule name="IMAP" dir=in action=allow protocol=tcp localport=143 2>$null
netsh advfirewall firewall add rule name="POP3" dir=in action=allow protocol=tcp localport=110 2>$null

Write-Host ""
Write-Host "  Email Server Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  MANUAL CONFIGURATION NEEDED:" -ForegroundColor Yellow
Write-Host "  1. Open hMailServer Administrator (Start Menu)" -ForegroundColor White
Write-Host "  2. Connect with password: (blank on first run)" -ForegroundColor White
Write-Host "  3. Add domain: aria.local" -ForegroundColor White
Write-Host "  4. Add accounts:" -ForegroundColor White
Write-Host "     - admin@aria.local     (AriaAdmin2026!)" -ForegroundColor White
Write-Host "     - analyst@aria.local   (AriaAnalyst2026!)" -ForegroundColor White
Write-Host "     - alerts@aria.local    (AriaAlerts2026!)" -ForegroundColor White
Write-Host "     - noreply@aria.local   (AriaNoreply2026!)" -ForegroundColor White
Write-Host ""
Write-Host "  OPNsense rules needed:" -ForegroundColor Yellow
Write-Host "  - LAN -> 10.0.1.100 port 25,143 (SMTP, IMAP)" -ForegroundColor White
Write-Host ""
Write-Host "  Test with Thunderbird or PowerShell:" -ForegroundColor Yellow
Write-Host "  Send-MailMessage -From 'admin@aria.local' -To 'analyst@aria.local' -Subject 'Test' -Body 'Hello' -SmtpServer 10.0.1.100" -ForegroundColor White
Write-Host ""
