#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detects short-lived network connections (beacons) by polling netstat.

.DESCRIPTION
    Polls netstat on the local host or a remote host over WinRM, compares
    each snapshot to the previous one in memory, and logs only connections
    that appeared or disappeared since the last poll. Run it while a
    suspected beacon is active, then check the log for repeating
    short-lived connections.

    Sampling limit: one poll takes as long as netstat itself needs plus the
    interval between polls, so a beacon that lives for less than one poll
    cycle can still be missed. Shorter intervals help but never guarantee
    a catch.

.PARAMETER ComputerName
    Host to monitor. Defaults to the local computer.

.PARAMETER Credential
    Credentials for a remote host. Not needed for local monitoring.

.PARAMETER IntervalSeconds
    Seconds between polls. Default 1.

.PARAMETER DurationMinutes
    Stop after this many minutes. Default 0 (run until Ctrl+C).

.PARAMETER OutputPath
    Log file for connection changes. Defaults to NetstatDiff.txt on the
    operator's Desktop.
#>
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$IntervalSeconds = 1,
    [int]$DurationMinutes = 0,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\NetstatDiff.txt"
)

$isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost')

function Get-NetstatSnapshot {
    $raw = if ($isLocal) {
        netstat -ano
    } else {
        $invokeParams = @{ ComputerName = $ComputerName }
        if ($Credential) { $invokeParams['Credential'] = $Credential }
        Invoke-Command @invokeParams -ScriptBlock { netstat -ano }
    }

    # Key: "PROTO local -> foreign", value: owning PID. UDP lines have no
    # state column, so the state group is optional.
    $snapshot = @{}
    foreach ($line in $raw) {
        if ($line -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:(\S+)\s+)?(\d+)\s*$') {
            $snapshot["$($Matches[1]) $($Matches[2]) -> $($Matches[3])"] = [int]$Matches[5]
        }
    }
    return $snapshot
}

$procNames = @{}

function Get-ProcessName {
    param([int]$ProcessId)
    if ($procNames.ContainsKey($ProcessId)) { return $procNames[$ProcessId] }
    $name = $null
    if ($isLocal) {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) { $name = $proc.ProcessName }
    }
    $procNames[$ProcessId] = $name
    return $name
}

function Format-Connection {
    param([string]$Connection, [int]$ProcessId)
    $procName = Get-ProcessName -ProcessId $ProcessId
    if ($procName) { return "$Connection [PID $ProcessId, $procName]" }
    return "$Connection [PID $ProcessId]"
}

$previous = Get-NetstatSnapshot
$endTime = if ($DurationMinutes -gt 0) { (Get-Date).AddMinutes($DurationMinutes) } else { $null }

Write-Host "Monitoring $ComputerName every $IntervalSeconds second(s). Press Ctrl+C to stop. Logging changes to $OutputPath" -ForegroundColor Cyan

while ($true) {
    if ($endTime -and (Get-Date) -ge $endTime) { break }

    Start-Sleep -Seconds $IntervalSeconds
    $current = Get-NetstatSnapshot

    $appeared = @($current.Keys | Where-Object { -not $previous.ContainsKey($_) })
    $gone = @($previous.Keys | Where-Object { -not $current.ContainsKey($_) })

    if ($appeared.Count -gt 0 -or $gone.Count -gt 0) {
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $lines = @()
        foreach ($conn in $appeared) {
            $lines += "[$stamp] NEW:    $(Format-Connection -Connection $conn -ProcessId $current[$conn])"
        }
        foreach ($conn in $gone) {
            $lines += "[$stamp] CLOSED: $(Format-Connection -Connection $conn -ProcessId $previous[$conn])"
        }
        $lines | Add-Content -Path $OutputPath
        $lines | ForEach-Object { Write-Host $_ }
    }

    $previous = $current
}

Write-Host "Monitoring stopped." -ForegroundColor Cyan
