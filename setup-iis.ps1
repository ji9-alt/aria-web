# ARIA IIS Setup - Windows Server 2025
# IIS reverse proxy to waitress WSGI server

Write-Host ""
Write-Host "  ARIA IIS Web Server Setup - Windows Server 2025" -ForegroundColor Red
Write-Host ""

# Step 1: Install waitress (production WSGI server)
Write-Host "[1/5] Installing production server (waitress)..." -ForegroundColor Yellow
pip install waitress
if ($LASTEXITCODE -ne 0) { Write-Host "  waitress install failed" -ForegroundColor Red; exit 1 }
Write-Host "  waitress installed" -ForegroundColor Green

# Step 2: Install IIS with all needed features
Write-Host "[2/5] Installing IIS Web Server..." -ForegroundColor Yellow
$features = @(
    "Web-Server",
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Default-Doc",
    "Web-Static-Content",
    "Web-Http-Errors",
    "Web-Http-Logging",
    "Web-Request-Monitor",
    "Web-Filtering",
    "Web-Mgmt-Tools",
    "Web-Mgmt-Console"
)
foreach ($f in $features) {
    Install-WindowsFeature -Name $f -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  IIS installed" -ForegroundColor Green

# Step 3: Download and install URL Rewrite + ARR
Write-Host "[3/5] Installing URL Rewrite and ARR modules..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tempDir = "$env:TEMP\aria-iis"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# URL Rewrite 2.1
$urlRewrite = "$tempDir\rewrite.msi"
$urlRewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
try {
    Invoke-WebRequest -Uri $urlRewriteUrl -OutFile $urlRewrite -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i `"$urlRewrite`" /qn" -Wait -NoNewWindow
    Write-Host "  URL Rewrite installed" -ForegroundColor Green
} catch {
    Write-Host "  URL Rewrite download failed" -ForegroundColor Yellow
    Write-Host "  Manual download: https://www.iis.net/downloads/microsoft/url-rewrite" -ForegroundColor Yellow
}

# ARR 3.0
$arr = "$tempDir\arr.msi"
$arrUrl = "https://download.microsoft.com/download/E/9/8/E9849D6A-020E-47E4-9FD0-A023E99B54EB/requestRouter_amd64.msi"
try {
    Invoke-WebRequest -Uri $arrUrl -OutFile $arr -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i `"$arr`" /qn" -Wait -NoNewWindow
    Write-Host "  ARR installed" -ForegroundColor Green
} catch {
    Write-Host "  ARR download failed" -ForegroundColor Yellow
    Write-Host "  Manual download: https://www.iis.net/downloads/microsoft/application-request-routing" -ForegroundColor Yellow
}

# Step 4: Enable ARR proxy and create reverse proxy rule
Write-Host "[4/5] Configuring reverse proxy (port 80 -> 5000)..." -ForegroundColor Yellow

# Enable ARR proxy via appcmd
$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
if (Test-Path $appcmd) {
    & $appcmd set config -section:system.webServer/proxy /enabled:true /commit:apphost 2>$null
    Write-Host "  ARR proxy enabled" -ForegroundColor Green
} else {
    Write-Host "  appcmd not found, IIS may not be fully installed" -ForegroundColor Yellow
}

# Write web.config for reverse proxy
$webConfig = "$env:SystemDrive\inetpub\wwwroot\web.config"
@"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="ARIA Reverse Proxy" stopProcessing="true">
                    <match url="(.*)" />
                    <action type="Rewrite" url="http://127.0.0.1:5000/{R:1}" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@ | Set-Content -Path $webConfig -Encoding UTF8
Write-Host "  Reverse proxy rule created" -ForegroundColor Green

# Step 5: Firewall and restart
Write-Host "[5/5] Firewall and restart..." -ForegroundColor Yellow
netsh advfirewall firewall add rule name="ARIA HTTP 80" dir=in action=allow protocol=tcp localport=80 2>$null
netsh advfirewall firewall add rule name="ARIA HTTPS 443" dir=in action=allow protocol=tcp localport=443 2>$null
# Keep 5000 open as fallback
netsh advfirewall firewall add rule name="ARIA Direct 5000" dir=in action=allow protocol=tcp localport=5000 2>$null

iisreset /restart

Write-Host ""
Write-Host "  IIS Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  HOW TO RUN:" -ForegroundColor Yellow
Write-Host "    cd C:\ARIA" -ForegroundColor White
Write-Host "    python serve.py" -ForegroundColor White
Write-Host ""
Write-Host "  ACCESS:" -ForegroundColor Yellow
Write-Host "    http://10.0.1.100/        (IIS on port 80)" -ForegroundColor White
Write-Host "    http://10.0.1.100:5000/   (direct fallback)" -ForegroundColor White
Write-Host ""
Write-Host "  RUN AS BACKGROUND SERVICE:" -ForegroundColor Yellow
Write-Host "    Start-Process python -ArgumentList 'serve.py' -WorkingDirectory 'C:\ARIA' -WindowStyle Hidden" -ForegroundColor White
Write-Host ""
