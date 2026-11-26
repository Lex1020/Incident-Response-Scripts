# Incident-Response-Scripts

PowerShell scripts for host-based incident response triage, built for IR classes and real investigations.

## Scripts

| Script | What it does |
| ------ | ------------ |
| `Initial_Triage_Script.ps1` | Collects system info, processes, network state, users, services, scheduled tasks, registry/WMI persistence, event logs and more — including process command lines, Defender detections, additional persistence, execution history, and deeper checks (recent installs, browser extensions, alternate data streams, USB history, root certificates) — from the local host or a remote host over WinRM. Saves a timestamped zip on the operator's Desktop. |
| `Netstat_Beacon_Detection.ps1` | Polls `netstat` and logs only connections that appear or disappear between polls, to catch short-lived beacons. |

## Requirements

- Windows PowerShell 5.1 or later
- Run elevated (Administrator) — `netstat -anob` and the Security event log require it
- Remote mode: WinRM enabled on the target, and credentials with admin rights there

## Usage

### Initial triage

```powershell
.\Initial_Triage_Script.ps1
```

Answer the prompts: `local` or `remote`, then pick a profile — Quick Scan (processes, network, users), Deep Scan (everything), or Custom Scan to choose individual categories. Output lands on your Desktop as `DiscoverOutput-<host>-<timestamp>.zip`, with a run log alongside it.

### Beacon detection

```powershell
.\Netstat_Beacon_Detection.ps1 -IntervalSeconds 1 -DurationMinutes 10
```

Monitors the local host every second for 10 minutes and logs new/closed connections to `NetstatDiff.txt` on your Desktop. Use `-ComputerName` and `-Credential` for a remote host. Omit `-DurationMinutes` to run until Ctrl+C.

**Sampling limit:** one poll takes as long as `netstat` itself needs plus the interval, so a beacon that lives for less than one poll cycle can still be missed. Shorter intervals help but never guarantee a catch.

## License

See `LICENSE`.
