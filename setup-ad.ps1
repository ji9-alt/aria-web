# ARIA Active Directory Setup - Windows Server 2025
# Sets up AD DS, creates domain, OUs, users, and groups

Write-Host ""
Write-Host "  ARIA Active Directory Setup" -ForegroundColor Red
Write-Host ""

$domainName = "aria.local"
$netbiosName = "ARIA"
$safeModePass = ConvertTo-SecureString "AriaRestore2026!" -AsPlainText -Force

# Step 1: Install AD DS Role
Write-Host "[1/4] Installing Active Directory Domain Services..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Write-Host "  AD DS installed" -ForegroundColor Green

# Step 2: Promote to Domain Controller
Write-Host "[2/4] Promoting to Domain Controller..." -ForegroundColor Yellow
Write-Host "  Domain: $domainName" -ForegroundColor White
Write-Host "  NetBIOS: $netbiosName" -ForegroundColor White

try {
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $domainName `
        -DomainNetbiosName $netbiosName `
        -SafeModeAdministratorPassword $safeModePass `
        -InstallDNS:$true `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true `
        -NoRebootOnCompletion:$true
    Write-Host "  Domain Controller promoted" -ForegroundColor Green
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host "  The server will reboot after promotion. Re-run this script after reboot to create OUs and users." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  SERVER WILL REBOOT. After reboot, run:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File setup-ad-users.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  Rebooting in 10 seconds..." -ForegroundColor Red
Start-Sleep -Seconds 10
Restart-Computer -Force
