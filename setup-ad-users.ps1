# ARIA AD Users & Groups Setup
# Run AFTER domain controller promotion and reboot

Write-Host ""
Write-Host "  ARIA AD - Users, Groups, and OUs" -ForegroundColor Red
Write-Host ""

Import-Module ActiveDirectory

$domain = "DC=aria,DC=local"

# Step 1: Create OUs
Write-Host "[1/3] Creating Organizational Units..." -ForegroundColor Yellow
$ous = @("IT", "Analysts", "Customers", "Servers", "Workstations")
foreach ($ou in $ous) {
    try {
        New-ADOrganizationalUnit -Name $ou -Path $domain -ProtectedFromAccidentalDeletion $true
        Write-Host "  OU created: $ou" -ForegroundColor Green
    } catch {
        Write-Host "  OU exists: $ou" -ForegroundColor Yellow
    }
}

# Step 2: Create Security Groups
Write-Host "[2/3] Creating Security Groups..." -ForegroundColor Yellow
$groups = @(
    @{Name="ARIA-Admins"; Path="OU=IT,$domain"; Desc="ARIA Platform Administrators"},
    @{Name="ARIA-Analysts"; Path="OU=Analysts,$domain"; Desc="Security Analysts"},
    @{Name="ARIA-Customers"; Path="OU=Customers,$domain"; Desc="ARIA Customers"},
    @{Name="ARIA-ReadOnly"; Path="OU=IT,$domain"; Desc="Read-only access to reports"}
)
foreach ($g in $groups) {
    try {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $g.Path -Description $g.Desc
        Write-Host "  Group created: $($g.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  Group exists: $($g.Name)" -ForegroundColor Yellow
    }
}

# Step 3: Create Users
Write-Host "[3/3] Creating Users..." -ForegroundColor Yellow
$defaultPass = ConvertTo-SecureString "AriaUser2026!" -AsPlainText -Force

$users = @(
    @{First="Admin"; Last="User"; User="admin.aria"; Group="ARIA-Admins"; OU="IT"; Title="Platform Administrator"},
    @{First="Sarah"; Last="Chen"; User="s.chen"; Group="ARIA-Analysts"; OU="Analysts"; Title="Senior Security Analyst"},
    @{First="Marcus"; Last="Wright"; User="m.wright"; Group="ARIA-Analysts"; OU="Analysts"; Title="Threat Intelligence Analyst"},
    @{First="Jordan"; Last="Blake"; User="j.blake"; Group="ARIA-Analysts"; OU="Analysts"; Title="Malware Analyst"},
    @{First="Alex"; Last="Morgan"; User="a.morgan"; Group="ARIA-Customers"; OU="Customers"; Title="Enterprise Customer"},
    @{First="Riley"; Last="Smith"; User="r.smith"; Group="ARIA-Customers"; OU="Customers"; Title="Customer"},
    @{First="Guest"; Last="User"; User="guest"; Group="ARIA-ReadOnly"; OU="Customers"; Title="Guest Access"}
)

foreach ($u in $users) {
    try {
        New-ADUser `
            -Name "$($u.First) $($u.Last)" `
            -GivenName $u.First `
            -Surname $u.Last `
            -SamAccountName $u.User `
            -UserPrincipalName "$($u.User)@aria.local" `
            -Path "OU=$($u.OU),$domain" `
            -AccountPassword $defaultPass `
            -Enabled $true `
            -Title $u.Title `
            -ChangePasswordAtLogon $false
        Add-ADGroupMember -Identity $u.Group -Members $u.User
        Write-Host "  User created: $($u.User) -> $($u.Group)" -ForegroundColor Green
    } catch {
        Write-Host "  User exists: $($u.User)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  AD Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Domain:    aria.local" -ForegroundColor White
Write-Host "  OUs:       IT, Analysts, Customers, Servers, Workstations" -ForegroundColor White
Write-Host "  Groups:    ARIA-Admins, ARIA-Analysts, ARIA-Customers, ARIA-ReadOnly" -ForegroundColor White
Write-Host "  Users:     admin.aria, s.chen, m.wright, j.blake, a.morgan, r.smith, guest" -ForegroundColor White
Write-Host "  Password:  AriaUser2026! (all users)" -ForegroundColor White
Write-Host ""
Write-Host "  To join a workstation to the domain:" -ForegroundColor Yellow
Write-Host "  Add-Computer -DomainName aria.local -Credential ARIA\admin.aria -Restart" -ForegroundColor White
Write-Host ""
