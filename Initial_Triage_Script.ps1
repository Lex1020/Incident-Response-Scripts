#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Host triage collection for incident response.

.DESCRIPTION
    Collects system info, processes, network state, users, services,
    scheduled tasks, registry/WMI persistence, event logs and more from the
    local host or a remote host over WinRM, and saves the results to a
    timestamped zip on the operator's Desktop.

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
        $menu = @("1. System Info","2. Directory Walk","3. Suspicious Executables","4. Network Info","5. Services","6. User Accounts","7. Processes","8. Scheduled Tasks","9. Registry & WMI","10. Event Logs","11. All of the above")
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
    $data += @(Add-TriageBlock 10 "Event Logs" { Get-WinEvent -LogName Security -MaxEvents 500 | Format-List | Out-String })
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
