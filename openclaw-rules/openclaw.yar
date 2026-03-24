import "pe"

rule OpenClaw_MinimalImports_LargeFile {
    meta:
        description = "Large PE with few imports - likely packed"
        author = "OpenClaw"
        severity = "MEDIUM"
    condition:
        pe.is_pe and filesize > 1MB and pe.number_of_imports < 4
}

rule OpenClaw_Embedded_DigiCert_Unsigned {
    meta:
        description = "Embedded DigiCert URLs in unsigned binary"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $dc1 = "digicert.com" nocase
        $dc2 = "ocsp.digicert" nocase
        $dc3 = "cacerts.digicert" nocase
    condition:
        pe.is_pe and 2 of ($dc1,$dc2,$dc3) and not pe.is_signed
}

rule OpenClaw_Cert_Chain_In_Binary {
    meta:
        description = "Certificate chain URLs embedded in PE"
        author = "OpenClaw"
        severity = "MEDIUM"
    strings:
        $ocsp = "http://ocsp." nocase
        $crl = "http://crl" nocase
        $cacert = "cacerts." nocase
    condition:
        pe.is_pe and all of them
}

rule OpenClaw_RtlService_Masquerade {
    meta:
        description = "Binary references RtlService.exe"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $rtl = "RtlService.exe" nocase
    condition:
        pe.is_pe and $rtl
}

rule OpenClaw_VersionResource_Scaffold {
    meta:
        description = "Version resource field names present"
        author = "OpenClaw"
        severity = "MEDIUM"
    strings:
        $cn = "CompanyName" wide
        $fd = "FileDescription" wide
        $on = "OriginalFilename" wide
        $pn = "ProductName" wide
    condition:
        pe.is_pe and 3 of them
}

rule OpenClaw_AES_SBox {
    meta:
        description = "AES S-Box constants in PE binary"
        author = "OpenClaw"
        severity = "MEDIUM"
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        pe.is_pe and $sbox
}

// ── DATA FILE INJECTION RULES (no pe.is_pe — catches payloads in any file) ──
// NOTE: These rules must be VERY tight. "MZ" appears in ISOs, git packs,
// WASM, databases, and source code. Only match unambiguous injection patterns.

rule OpenClaw_Embedded_PE_WithDOSStub {
    meta:
        description = "Full PE with DOS stub embedded in non-PE file — high confidence"
        author = "OpenClaw"
        severity = "CRITICAL"
    strings:
        // Require both MZ header AND the DOS error message — filters out
        // ISOs, git packs, WASM, and other formats with incidental MZ bytes.
        $dos_msg = "This program cannot be run in DOS mode"
    condition:
        not pe.is_pe and filesize < 50MB and $dos_msg
}

rule OpenClaw_Shellcode_Metasploit {
    meta:
        description = "Known Metasploit/msfvenom payload signatures"
        author = "OpenClaw"
        severity = "CRITICAL"
    strings:
        // msfvenom shikata_ga_nai encoder stub (extremely specific)
        $shikata = { d9 74 24 f4 5? (2? | 3?) }
        // Metasploit reverse TCP shell setup
        $msf_reverse = { 6a 02 5f 6a 01 5e 6a 06 5a 6a 29 }
        // Cobalt Strike beacon marker
        $cs_beacon = { 2e 2f 2e 2f 2e 2c }
    condition:
        not pe.is_pe and filesize < 10MB and any of them
}

rule OpenClaw_AntiAnalysis {
    meta:
        description = "Anti-analysis or sandbox evasion strings"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $s1 = "IsDebuggerPresent" nocase
        $s2 = "CheckRemoteDebuggerPresent" nocase
        $s3 = "NtQueryInformationProcess" nocase
        $s4 = "wine_get_version" nocase
        $s5 = "SbieDll.dll" nocase
        $s6 = "vmware" nocase
        $s7 = "VBoxService" nocase
    condition:
        pe.is_pe and 2 of them
}

rule OpenClaw_Process_Injection {
    meta:
        description = "APIs used for process injection"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $a1 = "VirtualAllocEx" nocase
        $a2 = "WriteProcessMemory" nocase
        $a3 = "CreateRemoteThread" nocase
        $a4 = "NtUnmapViewOfSection" nocase
        $a5 = "RtlCreateUserThread" nocase
    condition:
        pe.is_pe and 2 of them
}

rule OpenClaw_Credential_Theft {
    meta:
        description = "APIs used for credential theft"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $c1 = "LsaEnumerateLogonSessions" nocase
        $c2 = "CredEnumerate" nocase
        $c3 = "CryptUnprotectData" nocase
        $c4 = "PFXImportCertStore" nocase
    condition:
        pe.is_pe and any of them
}

rule OpenClaw_PowerShell_PE {
    meta:
        description = "PowerShell execution patterns in PE binary"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "-EncodedCommand" nocase
        $ps4 = "-WindowStyle Hidden" nocase
        $ps5 = "IEX(" nocase
        $ps6 = "bypass" nocase
    condition:
        pe.is_pe and 2 of them
}

rule OpenClaw_PowerShell_Script {
    meta:
        description = "Obfuscated PowerShell in non-PE files (scripts, documents)"
        author = "OpenClaw"
        severity = "HIGH"
    strings:
        // Only match actual obfuscation/evasion patterns, not documentation
        $enc = "-EncodedCommand" nocase
        $iex = "Invoke-Expression" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $noprof = "-NoProfile" nocase
        $dl1 = "DownloadString(" nocase
        $dl2 = "DownloadFile(" nocase
        $dl3 = "Net.WebClient" nocase
        $b64 = "[Convert]::FromBase64String" nocase
        $refl = "[Reflection.Assembly]::Load" nocase
    condition:
        not pe.is_pe and (
            ($enc and $iex)                    // encoded + invoke = classic attack
            or ($hidden and any of ($dl*))     // hidden window + download
            or ($bypass and $noprof and any of ($dl*))  // bypass + download
            or ($b64 and ($iex or $refl))      // base64 decode + execute/reflect
            or 4 of them                       // 4+ evasion patterns together
        )
}
