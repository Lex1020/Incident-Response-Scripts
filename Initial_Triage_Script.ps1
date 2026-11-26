#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Host triage collection for incident response.

.DESCRIPTION
    Collects system info, processes, network state, users, services,
    scheduled tasks, registry/WMI persistence, event logs and more from the
    local host or a remote host over WinRM, and saves the results to a
    timestamped zip on the operator's Desktop.

    Also covers process command lines, Defender detections, additional
    persistence (Startup, Winlogon, IFEO, AppInit), network configuration,
    execution history, service paths, BITS/shares/admins, and deeper checks
    (recent installs, browser extensions, alternate data streams, USB
    history, root certificates).

    Run locally or remotely; pick a Quick, Deep, or Custom profile to choose
    what gets collected.

.NOTES
    Requires elevation (netstat -anob and the Security event log need admin).
    Remote mode requires WinRM on the target and credentials with admin rights.
#>

# Ask user to run locally or remotely
$runLocal = Read-Host "Run script locally or remotely? Enter 'local' or 'remote'"

if ($runLocal -eq 'remote') {
    $cred = Get-Credential
    $remoteIP = Read-Host "Enter the IP address of the remote system"
    $targetName = $remoteIP
} else {
    $remoteIP = $env:COMPUTERNAME
    $targetName = $remoteIP
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sanitizedTarget = $targetName -replace '[^0-9A-Za-z]', '_'
$localOutputPath = "$env:USERPROFILE\Desktop\DiscoverOutput-$sanitizedTarget-$timestamp.txt"
$localZipPath = "$env:USERPROFILE\Desktop\DiscoverOutput-$sanitizedTarget-$timestamp.zip"
$localLogPath = "$env:USERPROFILE\Desktop\DiscoverLog-$sanitizedTarget-$timestamp.txt"

$log = @()

Write-Host "Select a profile or customize your scan:" -ForegroundColor Cyan
$profiles = @(
    "1. Quick Scan (Processes, Network, Users)",
    "2. Deep Scan (Everything)",
    "3. Custom Scan"
)
$profiles | ForEach-Object { Write-Host $_ }
$profileChoice = Read-Host "Enter profile number"

switch ($profileChoice) {
    '1' { $selection = '4,6,7'; $collectAll = $false }
    '2' { $selection = '11'; $collectAll = $true }
    default {
        Write-Host "Select data to collect:" -ForegroundColor Cyan
        $menu = @("1. System Info","2. Directory Walk","3. Suspicious Executables","4. Network Info","5. Services","6. User Accounts","7. Processes","8. Scheduled Tasks","9. Registry & WMI","10. Event Logs","11. All of the above","12. Process Command Lines","13. Defender Status & Detections","14. Suspicious Process Paths","15. Additional Persistence","16. Network Configuration","17. Execution History","18. Service Binary Paths","19. BITS Jobs, Shares & Admins","20. Deeper Checks")
        $menu | ForEach-Object { Write-Host $_ }
        $selection = Read-Host "Enter numbers separated by commas (e.g., 1,3,5 or 11)"
        $collectAll = ($selection -split ',' | ForEach-Object { $_.Trim() }) -contains '11'
    }
}

# One collection definition, used for local and remote runs alike.
# Add-TriageBlock returns its block instead of appending to $data:
# assignments inside a function are local to that function, so the old
# version's appends were silently discarded and the output only ever held
# the Started/Completed lines. Call sites wrap the call in @(...) so a
# skipped block appends nothing instead of a $null entry.
$collectScript = {
    param($selection, $collectAll)

    $selection = $selection -split ',' | ForEach-Object { $_.Trim() }
    $data = @()
    $data += "====== Triage Script Started: $(Get-Date) ======"

    function Add-TriageBlock {
        param($condition, $label, $script)
        if ($collectAll -or $selection -contains $condition) {
            "====== $label ======"
            try { & $script } catch { "[Error] $_" }
        }
    }

    $data += @(Add-TriageBlock 1 "System Info" { systeminfo })
    $data += @(Add-TriageBlock 2 "Directory Walk" { Get-ChildItem -Path $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue | Out-String })
    $data += @(Add-TriageBlock 3 "Suspicious Executables" {
        Get-ChildItem -Path $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(exe|ps1|ps2|psc1|psc2|py|pif|msi|scr|hta|chm|jar|bat|cmd|vbs|vbe|reg|inf)$' -and
                ($_.LastWriteTime -gt (Get-Date).AddDays(-30) -or $_.FullName -match '\\AppData\\(Local\\Temp|Roaming)\\|\\Temp\\|\\Public\\') } |
            Select-Object FullName, Length, LastWriteTime | Out-String
    })
    $data += @(Add-TriageBlock 4 "NetStat" { netstat -anob })
    $data += @(Add-TriageBlock 4 "Network Connections" { Get-NetTCPConnection | Out-String })
    $data += @(Add-TriageBlock 4 "Net Start" { net start })
    $data += @(Add-TriageBlock 5 "Services" { Get-Service | Select-Object Name, DisplayName, Status, StartType | Out-String })
    $data += @(Add-TriageBlock 6 "User Accounts" { Get-LocalUser | Out-String })
    $data += @(Add-TriageBlock 7 "Running Processes" { Get-Process | Select-Object ProcessName, Id, Path | Out-String })
    $data += @(Add-TriageBlock 8 "Scheduled Tasks" {
        Get-ScheduledTask | Where-Object { $_.Author -notlike 'Microsoft*' -and $_.Author -notlike '*@%SystemRoot%\\*' } |
            Select-Object TaskName, TaskPath, Author, Actions, Triggers, Description, State | Out-String
    })
    $data += @(Add-TriageBlock 8 "Scheduled Jobs" { Get-ScheduledJob | Out-String })
    $data += @(Add-TriageBlock 9 "Firewall Status" { Get-NetFirewallProfile | Out-String })
    $data += @(Add-TriageBlock 10 "Event Logs (Targeted, last 48h)" {
        $eventFilter = @{ LogName = 'Security'; StartTime = (Get-Date).AddDays(-2) }
        $targetIds = @(4625, 4672, 4720, 4697, 7045)
        Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue |
            Where-Object { $targetIds -contains $_.Id } |
            Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List | Out-String
        "--- RDP Logons (4624 Type 10, last 48h) ---"
        try {
            Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -eq 4624 -and $_.Properties[8].Value -eq 10 } |
                Select-Object TimeCreated, Message | Format-List | Out-String
        } catch { "[Error] RDP logon query failed: $_" }
    })
    $data += @(Add-TriageBlock 9 "Registry Run Keys (Current User)" {
        Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-String
        Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Out-String
    })
    $data += @(Add-TriageBlock 9 "Registry Run Keys (Local Machine)" {
        Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-String
        Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Out-String
    })
    $data += @(Add-TriageBlock 9 "WMI Persistence" {
        Get-CimInstance -Namespace "root/subscription" -Class "__EventFilter" | Out-String
        Get-CimInstance -Namespace "root/subscription" -Class "CommandLineEventConsumer" | Out-String
        Get-CimInstance -Namespace "root/subscription" -Class "FilterToConsumerBinding" | Out-String
    })
    $data += @(Add-TriageBlock 9 "DNS Cache" { ipconfig /displaydns })
    $data += @(Add-TriageBlock 9 "Modified Files (7 Days)" {
        Get-ChildItem -Path "C:\Users\*" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object FullName, LastWriteTime | Out-String
    })
    $data += @(Add-TriageBlock 9 "Environment Variables" { Get-ChildItem Env: | Out-String })
    $data += @(Add-TriageBlock 9 "Suspicious Parent-Child Process Pairs" {
        $suspiciousParents = @('winword.exe','excel.exe','powerpnt.exe','outlook.exe','iexplore.exe','msedge.exe','chrome.exe','firefox.exe','wscript.exe','cscript.exe','mshta.exe')
        $suspiciousChildren = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe')
        $procs = Get-CimInstance Win32_Process
        $nameById = @{}
        $procs | ForEach-Object { $nameById[$_.ProcessId] = $_.Name }
        $procs | Where-Object {
            $_.ParentProcessId -ne 0 -and $nameById.ContainsKey($_.ParentProcessId) -and
            (($suspiciousParents -contains $nameById[$_.ParentProcessId] -and $suspiciousChildren -contains $_.Name) -or
             ($nameById[$_.ParentProcessId] -eq 'explorer.exe' -and $_.Name -match '^(powershell|pwsh|cmd)\.exe$'))
        } | Select-Object Name, ProcessId, @{N='Parent';E={$nameById[$_.ParentProcessId]}}, ParentProcessId | Out-String
    })
    $data += @(Add-TriageBlock 9 "Windows Defender Exclusions" {
        Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess | Out-String
    })

    $data += @(Add-TriageBlock 12 "Process Command Lines" {
        $suspiciousPatterns = @('-enc', '-EncodedCommand', 'DownloadString', 'Invoke-Expression', '\bIEX\b', 'WindowStyle Hidden', '-w hidden', 'FromBase64String', 'rundll32', 'mshta', 'regsvr32', 'certutil.*-urlcache', 'bitsadmin', 'wscript', 'cscript', 'Net.WebClient', 'DownloadFile')
        Get-CimInstance Win32_Process | ForEach-Object {
            $flag = ""
            foreach ($pat in $suspiciousPatterns) {
                if ($_.CommandLine -and $_.CommandLine -match $pat) { $flag = " [SUSPICIOUS: $pat]"; break }
            }
            "$($_.Name) (PID $($_.ProcessId), Parent $($_.ParentProcessId))$flag`n  Path: $($_.ExecutablePath)`n  Cmd: $($_.CommandLine)"
        } | Out-String
    })
    $data += @(Add-TriageBlock 13 "Defender Status & Detections" {
        Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge | Out-String
        Get-MpThreatDetection | Select-Object ThreatID, ThreatName, SeverityID, DetectionTime, Resources | Out-String
    })
    $data += @(Add-TriageBlock 14 "Suspicious Process Paths" {
        $systemBinaries = @('smss.exe','csrss.exe','wininit.exe','winlogon.exe','services.exe','lsass.exe','svchost.exe','spoolsv.exe','dwm.exe','explorer.exe','taskhost.exe','taskhostw.exe','dllhost.exe','conhost.exe','fontdrvhost.exe','sihost.exe')
        $systemDirs = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")
        "--- Known system binaries running outside System32 / SysWOW64, or image missing from disk ---"
        Get-CimInstance Win32_Process | Where-Object {
            $_.ExecutablePath -and (
                ($systemBinaries -contains $_.Name -and ($systemDirs -notcontains (Split-Path $_.ExecutablePath -Parent))) -or
                (-not (Test-Path $_.ExecutablePath))
            )
        } | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath | Out-String
        "--- Processes with no image path (includes protected system processes; investigate unfamiliar names) ---"
        Get-CimInstance Win32_Process | Where-Object { -not $_.ExecutablePath } |
            Select-Object Name, ProcessId, ParentProcessId | Out-String
    })
    $data += @(Add-TriageBlock 15 "Additional Persistence" {
        "--- Startup Folders ---"
        Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue | Select-Object Name, FullName | Out-String
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName | Out-String
        "--- Winlogon ---"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object Shell, Userinit | Out-String
        "--- IFEO Debugger Hijacks ---"
        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Debugger } | Select-Object @{N='Image';E={$_.PSChildName}}, Debugger } | Out-String
        "--- AppInit DLLs ---"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs, LoadAppInit_DLLs | Out-String
    })
    $data += @(Add-TriageBlock 16 "Network Configuration" {
        "--- Hosts File (non-comment lines) ---"
        Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } | Out-String
        "--- Proxy Settings ---"
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Out-String
        "--- ARP Table ---"
        arp -a | Out-String
        "--- Route Table ---"
        route print | Out-String
    })
    $data += @(Add-TriageBlock 17 "Execution History" {
        "--- PowerShell Console History (last 200 lines) ---"
        try { $historyPath = (Get-PSReadLineOption).HistorySavePath } catch { $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" }
        if ($historyPath -and (Test-Path $historyPath)) { Get-Content $historyPath -Tail 200 -ErrorAction SilentlyContinue | Out-String }
        "--- RunMRU ---"
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue | Out-String
        "--- RecentDocs ---"
        $recentDocs = Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
        if ($recentDocs) { $recentDocs.GetValueNames() | Out-String }
    })
    $data += @(Add-TriageBlock 18 "Service Binary Paths" {
        $writableRoots = @("$env:TEMP", "$env:TMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:PUBLIC", "$env:SystemDrive\Users\Public", "C:\ProgramData")
        Get-CimInstance Win32_Service | ForEach-Object {
            $flag = ""
            if ($_.PathName) {
                if ($_.PathName -match '^"([^"]+)"') { $exePath = $Matches[1] } else { $exePath = ($_.PathName -split '\s+')[0] }
                foreach ($root in $writableRoots) {
                    if ($exePath -like "$root*") { $flag = " [SUSPICIOUS PATH]"; break }
                }
            }
            "$($_.Name) ($($_.DisplayName)) - $($_.State)/$($_.StartMode)$flag`n  Path: $($_.PathName)"
        } | Out-String
    })
    $data += @(Add-TriageBlock 19 "BITS Jobs, Shares & Admins" {
        "--- BITS Jobs ---"
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, JobState, OwnerAccount | Out-String
        "--- SMB Shares ---"
        Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description | Out-String
        "--- Local Administrators ---"
        Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, PrincipalSource, ObjectClass | Out-String
        "--- Accounts with password set in last 30 days (new or recently changed) ---"
        Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.PasswordLastSet -gt (Get-Date).AddDays(-30) } |
            Select-Object Name, Enabled, PasswordLastSet, LastLogon | Out-String
    })
    $data += @(Add-TriageBlock 20 "Deeper Checks" {
        "--- Installed Programs (last 7 days) ---"
        $cutoff = (Get-Date).AddDays(-7).ToString('yyyyMMdd')
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.InstallDate -match '^\d{8}$' -and $_.InstallDate -ge $cutoff } |
            Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | Out-String
        "--- Browser Extensions ---"
        foreach ($browserPath in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions")) {
            if (Test-Path $browserPath) {
                Get-ChildItem $browserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $manifest = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($manifest) {
                        $info = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                        "$($_.Name): $($info.name) v$($info.version)"
                    } else { "$($_.Name): (no manifest found)" }
                } | Out-String
            }
        }
        "--- Alternate Data Streams (Temp / AppData) ---"
        foreach ($scanPath in @($env:TEMP, "$env:LOCALAPPDATA\Temp", $env:APPDATA)) {
            if ($scanPath -and (Test-Path $scanPath)) {
                Get-ChildItem -Path $scanPath -Recurse -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' } |
                    Select-Object PSPath, Stream, Length | Out-String
            }
        }
        "--- USB Device History ---"
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue |
            Select-Object PSChildName | Out-String
        "--- Root Certificate Store (self-signed / non-standard issuers; heuristic, a baseline comparison is better) ---"
        $knownIssuers = @('Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 'Entrust', 'GoDaddy', 'Let''s Encrypt', 'COMODO', 'VeriSign', 'Thawte', 'GeoTrust', 'QuoVadis', 'IdenTrust', 'Starfield', 'Amazon', 'Google')
        Get-ChildItem "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | ForEach-Object {
            $issuer = $_.Issuer
            $known = $false
            foreach ($k in $knownIssuers) { if ($issuer -match [regex]::Escape($k)) { $known = $true; break } }
            if (-not $known) { "$($_.Thumbprint) | Subject: $($_.Subject) | Issuer: $issuer | Expires: $($_.NotAfter)" }
        } | Out-String
    })
    $data += "====== Triage Script Completed: $(Get-Date) ======"
    return $data
}

try {
    if ($runLocal -eq 'remote') {
        Invoke-Command -ComputerName $remoteIP -Credential $cred -ScriptBlock $collectScript -ArgumentList $selection, $collectAll |
            Out-File -FilePath $localOutputPath -Encoding UTF8
    } else {
        & $collectScript -selection $selection -collectAll $collectAll |
            Out-File -FilePath $localOutputPath -Encoding UTF8
    }

    Compress-Archive -Path $localOutputPath -DestinationPath $localZipPath -Force
    Remove-Item -Path $localOutputPath -Force

    $log += "[$timestamp] Successfully ran triage on $targetName and saved to $localZipPath"
} catch {
    $log += "[$timestamp] Failed to run triage on $targetName. Error: $_"
}

$log | Out-File -FilePath $localLogPath -Encoding UTF8 -Append
