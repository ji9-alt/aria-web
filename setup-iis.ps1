# ARIA Full IIS Hosting - Windows Server 2025
# IIS manages the entire Python app via HttpPlatformHandler
# No manual 'python serve.py' needed - IIS handles everything

Write-Host ""
Write-Host "  ARIA - Full IIS Deployment (Windows Server 2025)" -ForegroundColor Red
Write-Host ""

$ariaPath = "C:\ARIA"
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Host "  Python not found! Install Python first." -ForegroundColor Red
    exit 1
}
Write-Host "  Python found: $pythonPath" -ForegroundColor Green

# Step 1: Install waitress
Write-Host "[1/6] Installing waitress WSGI server..." -ForegroundColor Yellow
pip install waitress
Write-Host "  Done" -ForegroundColor Green

# Step 2: Install IIS with all needed features
Write-Host "[2/6] Installing IIS Web Server features..." -ForegroundColor Yellow
$features = @(
    "Web-Server",
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Default-Doc",
    "Web-Static-Content",
    "Web-Http-Errors",
    "Web-Http-Logging",
    "Web-Log-Libraries",
    "Web-Request-Monitor",
    "Web-Filtering",
    "Web-Stat-Compression",
    "Web-Mgmt-Tools",
    "Web-Mgmt-Console",
    "Web-Scripting-Tools"
)
foreach ($f in $features) {
    Install-WindowsFeature -Name $f -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  IIS installed" -ForegroundColor Green

# Step 3: Install HttpPlatformHandler
Write-Host "[3/6] Installing HttpPlatformHandler..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tempDir = "$env:TEMP\aria-iis"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$hphUrl = "https://download.microsoft.com/download/6/E/5/6E5AA297-A610-47FF-BF3E-1311B3284B07/httpPlatformHandler_amd64.msi"
$hphPath = "$tempDir\httpPlatformHandler.msi"
try {
    Invoke-WebRequest -Uri $hphUrl -OutFile $hphPath -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i `"$hphPath`" /qn" -Wait -NoNewWindow
    Write-Host "  HttpPlatformHandler installed" -ForegroundColor Green
} catch {
    Write-Host "  Download failed - trying alternative..." -ForegroundColor Yellow
    # Try WebPI or manual
    Write-Host "  If this fails, download HttpPlatformHandler from:" -ForegroundColor Yellow
    Write-Host "  https://www.iis.net/downloads/microsoft/httpplatformhandler" -ForegroundColor White
}

# Step 4: Create IIS site pointing to ARIA
Write-Host "[4/6] Configuring IIS site..." -ForegroundColor Yellow

Import-Module WebAdministration -ErrorAction SilentlyContinue

# Remove default site
try {
    Remove-WebSite -Name "Default Web Site" -ErrorAction SilentlyContinue
} catch {}

# Create ARIA site on port 80
try {
    New-WebSite -Name "ARIA" -PhysicalPath $ariaPath -Port 80 -IPAddress "*" -Force
    Write-Host "  ARIA site created on port 80" -ForegroundColor Green
} catch {
    Write-Host "  Could not create site via PowerShell, trying appcmd..." -ForegroundColor Yellow
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    & $appcmd delete site "Default Web Site" 2>$null
    & $appcmd add site /name:"ARIA" /physicalPath:"$ariaPath" /bindings:http/*:80:
    Write-Host "  ARIA site created via appcmd" -ForegroundColor Green
}

# Step 5: Write web.config for HttpPlatformHandler
Write-Host "[5/6] Writing web.config (HttpPlatformHandler)..." -ForegroundColor Yellow

$webConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="httpPlatformHandler" path="*" verb="*" modules="httpPlatformHandler" resourceType="Unspecified" />
    </handlers>
    <httpPlatform processPath="$pythonPath"
                  arguments="serve.py"
                  stdoutLogEnabled="true"
                  stdoutLogFile=".\logs\aria"
                  startupTimeLimit="60"
                  requestTimeout="00:05:00"
                  processesPerApplication="1">
      <environmentVariables>
        <environmentVariable name="ARIA_PORT" value="%HTTP_PLATFORM_PORT%" />
      </environmentVariables>
    </httpPlatform>
  </system.webServer>
</configuration>
"@

Set-Content -Path "$ariaPath\web.config" -Value $webConfigContent -Encoding UTF8
Write-Host "  web.config written" -ForegroundColor Green

# Create logs directory
New-Item -ItemType Directory -Path "$ariaPath\logs" -Force | Out-Null

# Step 6: Update serve.py to use the port IIS assigns
Write-Host "[6/6] Firewall and permissions..." -ForegroundColor Yellow

# Grant IIS_IUSRS access to the ARIA directory
icacls $ariaPath /grant "IIS_IUSRS:(OI)(CI)F" /T /Q
icacls $ariaPath /grant "IUSR:(OI)(CI)F" /T /Q

# Firewall
netsh advfirewall firewall add rule name="ARIA HTTP 80" dir=in action=allow protocol=tcp localport=80 2>$null
netsh advfirewall firewall add rule name="ARIA HTTPS 443" dir=in action=allow protocol=tcp localport=443 2>$null

# Restart IIS
iisreset /restart

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Green
Write-Host "  ARIA is now hosted on IIS!" -ForegroundColor Green
Write-Host "  ========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  URL: http://10.0.1.100/" -ForegroundColor White
Write-Host ""
Write-Host "  IIS manages the Python process automatically." -ForegroundColor White
Write-Host "  No need to run 'python serve.py' manually." -ForegroundColor White
Write-Host ""
Write-Host "  Manage via: IIS Manager (inetmgr)" -ForegroundColor Yellow
Write-Host "  Logs at:    C:\ARIA\logs\" -ForegroundColor Yellow
Write-Host ""
