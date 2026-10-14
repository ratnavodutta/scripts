<#
.SYNOPSIS
    Interactive wrapper around Sysinternals PsPing for finding network drops (TCP or ICMP).

.DESCRIPTION
    Prompts for:
      1. Target IP address
      2. Probe type  - TCP (asks for a port) or ICMP
      3. Packet count - 5 packets, a custom number, or continuous (until Ctrl+C)
      4. Output mode - live on screen, or quiet (file only; Ctrl+C stops and finalises the log)

    Every line is stamped with the local date/time of this machine and written to a log
    file. Failed probes (timeouts, unreachable, refused...) are tagged [DROP], and runs of
    consecutive drops are logged as outages with start time, end time and duration.
    A summary is always written, including when the run is stopped with Ctrl+C.

    If TCP is chosen and no valid port is given, the user is asked whether to restart.

.PARAMETER Interval
    Seconds between probes (default 1).

.PARAMETER PsPingPath
    Optional full path to psping.exe / psping64.exe. If omitted, the script looks in the
    script folder and then in PATH. If PsPing is not found the user is offered an automatic
    download (Sysinternals Live) into %LOCALAPPDATA%\PsPing, added to the user PATH.

.PARAMETER LogDirectory
    Folder for the .txt log files (default: .\logs next to the script).

.EXAMPLE
    .\Invoke-PsPingProbe.ps1
    .\Invoke-PsPingProbe.ps1 -Interval 2 -PsPingPath C:\PSTools\psping64.exe
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3600)]
    [int]$Interval = 1,

    [string]$PsPingPath,

    [string]$LogDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $LogDirectory) { $LogDirectory = Join-Path $ScriptDir 'logs' }

# ---------------------------------------------------------------- helpers
function Get-Stamp {
    # Local machine time, with UTC offset so logs stay unambiguous.
    Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'
}

function Find-PsPing {
    param([string]$Path)

    if ($Path) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Resolve-Path -LiteralPath $Path).Path }
        throw "PsPing not found at '$Path'."
    }
    foreach ($name in 'psping64.exe', 'psping.exe') {
        $local = Join-Path $ScriptDir $name
        if (Test-Path -LiteralPath $local -PathType Leaf) { return $local }
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Install-PsPing {
    # Downloads PsPing from Sysinternals Live into a per-user folder and adds that folder to the
    # user's PATH (no admin rights needed). Returns the path to the exe, or $null on failure.
    $installDir = Join-Path $env:LOCALAPPDATA 'PsPing'
    $exeName    = if ([Environment]::Is64BitOperatingSystem) { 'psping64.exe' } else { 'psping.exe' }
    $url        = "https://live.sysinternals.com/$exeName"
    $target     = Join-Path $installDir $exeName
    $temp       = Join-Path ([System.IO.Path]::GetTempPath()) ("{0}.{1}.download" -f $exeName, [guid]::NewGuid().ToString('N'))

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-Host "Downloading $url ..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $url -OutFile $temp -UseBasicParsing

        # Only keep the file if it carries a valid Microsoft signature.
        $sig = Get-AuthenticodeSignature -LiteralPath $temp
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw "Downloaded file failed signature check (status: $($sig.Status))."
        }

        if (-not (Test-Path -LiteralPath $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
        Move-Item -LiteralPath $temp -Destination $target -Force

        # Persist to the user PATH and refresh the current session.
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (($userPath -split ';') -contains $installDir)) {
            $newPath = if ($userPath) { "$($userPath.TrimEnd(';'));$installDir" } else { $installDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        }
        if (-not (($env:Path -split ';') -contains $installDir)) { $env:Path = "$env:Path;$installDir" }

        Write-Host "PsPing installed to $installDir and added to your user PATH." -ForegroundColor Green
        return $target
    }
    catch {
        Write-Host "PsPing download/installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Download it manually from https://learn.microsoft.com/sysinternals/downloads/psping' -ForegroundColor Yellow
        return $null
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
}

function Read-YesNo {
    param([string]$Prompt)
    while ($true) {
        $answer = (Read-Host "$Prompt (Y/N)").Trim()
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$')  { return $false }
        Write-Host 'Please answer Y or N.' -ForegroundColor Yellow
    }
}

function Read-TargetIp {
    while ($true) {
        $text = (Read-Host 'Enter target IP address').Trim()
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($text, [ref]$ip) -and $text -match '[.:]') { return $ip }
        Write-Host "'$text' is not a valid IPv4/IPv6 address." -ForegroundColor Yellow
    }
}

function Read-Protocol {
    while ($true) {
        $choice = (Read-Host 'Select probe type: [1] TCP  [2] ICMP').Trim().ToUpper()
        switch ($choice) {
            { $_ -in '1', 'TCP' }  { return 'TCP' }
            { $_ -in '2', 'ICMP' } { return 'ICMP' }
            default { Write-Host 'Enter 1/TCP or 2/ICMP.' -ForegroundColor Yellow }
        }
    }
}

# Returns a port number, -1 to restart the script, or $null to exit.
function Read-TcpPort {
    $text = (Read-Host 'Enter TCP port (1-65535)').Trim()
    $port = 0
    if ($text -and [int]::TryParse($text, [ref]$port) -and $port -ge 1 -and $port -le 65535) { return $port }

    if ($text) { Write-Host "'$text' is not a valid port." -ForegroundColor Yellow }
    else       { Write-Host 'No port number was provided.' -ForegroundColor Yellow }

    if (Read-YesNo 'Restart the script?') { return -1 }
    return $null
}

# Returns 0 for continuous, otherwise the packet count.
function Read-PacketCount {
    while ($true) {
        $choice = (Read-Host 'Packets to send: [1] 5 packets  [2] Custom number  [3] Continuous (until Ctrl+C)').Trim()
        switch ($choice) {
            '1' { return 5 }
            '3' { return 0 }
            '2' {
                $n = 0
                $text = (Read-Host 'How many packets? (1-1000000)').Trim()
                if ([int]::TryParse($text, [ref]$n) -and $n -ge 1 -and $n -le 1000000) { return $n }
                Write-Host "'$text' is not a valid number." -ForegroundColor Yellow
            }
            default { Write-Host 'Enter 1, 2 or 3.' -ForegroundColor Yellow }
        }
    }
}

# Returns $true for live output, $false for quiet (file only).
function Read-OutputMode {
    while ($true) {
        $choice = (Read-Host 'Output: [1] Live on screen  [2] Quiet - save to file only (Ctrl+C to stop and save)').Trim()
        switch ($choice) {
            '1' { return $true }
            '2' { return $false }
            default { Write-Host 'Enter 1 or 2.' -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------- probe engine
$script:DropPattern = '(?i)timed out|unreachable|could not connect|refused|no route|general failure|ttl expired|failed|error|unknown host|could not (find|resolve)'
$script:OkPattern   = '(?i)^\s*(Reply from|Connecting to).*:\s*[\d.,]+\s*ms\s*$'
$script:SkipPattern = '(?i)^\s*(Sent\b|Minimum\b|Approximate\b|Ping statistics|TCP (connect|ping)|Latency)'

function Write-LogLine {
    param([string]$Text, [string]$Color)
    $entry = "[$(Get-Stamp)] $Text"
    Add-Content -LiteralPath $script:LogFile -Value $entry -Encoding UTF8
    if ($Color) { Write-Host $entry -ForegroundColor $Color } else { Write-Host $entry }
}

# Same as Write-LogLine but only prints to the console when running live.
function Write-Quiet {
    param([string]$Text, [string]$Color)
    $entry = "[$(Get-Stamp)] $Text"
    Add-Content -LiteralPath $script:LogFile -Value $entry -Encoding UTF8
    if ($script:Live -or $Color -eq 'Red' -or $Color -eq 'Green') {
        if ($Color) { Write-Host $entry -ForegroundColor $Color } else { Write-Host $entry }
    }
}

function Close-Outage {
    param([switch]$AtEnd)
    if ($null -eq $script:OutageStart) { return }
    $end = Get-Date
    $dur = [math]::Round(($end - $script:OutageStart).TotalSeconds, 1)
    $rec = [pscustomobject]@{
        Start = $script:OutageStart.ToString('yyyy-MM-dd HH:mm:ss')
        End   = $end.ToString('yyyy-MM-dd HH:mm:ss')
        Lost  = $script:OutageLost
        Secs  = $dur
    }
    $script:Outages.Add($rec)
    if ($AtEnd) {
        Write-Quiet "[OUTAGE ONGOING AT END] Began $($rec.Start), $($rec.Lost) probe(s) lost, ~$($rec.Secs)s, no recovery before the run ended." 'Red'
    } else {
        Write-Quiet "[RECOVERED] Connectivity restored. Outage began $($rec.Start), $($rec.Lost) probe(s) lost, ~$($rec.Secs)s." 'Green'
    }
    $script:OutageStart = $null
    $script:OutageLost  = 0
}

function Invoke-ProbeLine {
    param([string]$Line)

    if ($Line -notmatch $script:SkipPattern -and $Line -match $script:DropPattern) {
        $script:Lost++
        if ($null -eq $script:OutageStart) {
            $script:OutageStart = Get-Date
            $script:OutageLost  = 0
        }
        $script:OutageLost++
        Write-Quiet "[DROP] $Line" 'Red'
        return
    }
    if ($Line -match $script:OkPattern) {
        $script:Ok++
        Close-Outage
        Write-Quiet $Line
        return
    }
    Write-Quiet $Line
}

function Write-Summary {
    Close-Outage -AtEnd
    $total = $script:Ok + $script:Lost
    $pct   = if ($total) { [math]::Round(100 * $script:Lost / $total, 2) } else { 0 }
    $run   = (Get-Date) - $script:StartTime

    Write-LogLine '----------------------------- SUMMARY -----------------------------' 'Cyan'
    Write-LogLine ("Started : {0:yyyy-MM-dd HH:mm:ss}   Ended : {1:yyyy-MM-dd HH:mm:ss}   Duration : {2:hh\:mm\:ss}" -f $script:StartTime, (Get-Date), $run) 'Cyan'
    Write-LogLine "Probes  : $total   Successful : $($script:Ok)   Dropped : $($script:Lost)   Loss : $pct%" 'Cyan'
    if ($script:Outages.Count -eq 0) {
        Write-LogLine 'Outages : none detected' 'Cyan'
    } else {
        Write-LogLine "Outages : $($script:Outages.Count)" 'Yellow'
        foreach ($o in $script:Outages) {
            Write-LogLine "  - $($o.Start) -> $($o.End)  ($($o.Lost) lost, ~$($o.Secs)s)" 'Yellow'
        }
    }
    Write-LogLine '-------------------------------------------------------------------' 'Cyan'
}

function Invoke-Probe {
    param(
        [string]$Exe,
        [System.Net.IPAddress]$Ip,
        [string]$Protocol,
        [int]$Port,
        [int]$Count,        # 0 = continuous
        [bool]$Live,
        [string]$LogFile
    )

    $script:LogFile     = $LogFile
    $script:Live        = $Live
    $script:Ok          = 0
    $script:Lost        = 0
    $script:OutageStart = $null
    $script:OutageLost  = 0
    $script:Outages     = New-Object System.Collections.Generic.List[object]
    $script:StartTime   = Get-Date

    $ipText = $Ip.ToString()
    if ($Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $ipText = "[$ipText]" }

    # PsPing: "host" = ICMP ping, "host:port" = TCP connect ping.
    $destination = if ($Protocol -eq 'TCP') { "${ipText}:$Port" } else { $ipText }
    $psArgs = @('-accepteula', '-i', $Interval, '-w', 0)         # -w 0: no warm-up, so every attempt is counted
    $psArgs += if ($Count -eq 0) { '-t' } else { @('-n', $Count) }
    $psArgs += $destination

    $countText = if ($Count -eq 0) { 'continuous' } else { $Count }
    Write-LogLine "===== Probe started | Host: $env:COMPUTERNAME | Type: $Protocol | Target: $destination | Packets: $countText | Interval: ${Interval}s =====" 'Cyan'
    Write-LogLine "Command: $(Split-Path $Exe -Leaf) $($psArgs -join ' ')"
    if (-not $Live) {
        Write-Host "Quiet mode: writing to $LogFile" -ForegroundColor Cyan
        Write-Host 'Only drops/recoveries are shown here. Press Ctrl+C to stop and save the summary.' -ForegroundColor Cyan
    } elseif ($Count -eq 0) {
        Write-Host 'Press Ctrl+C to stop and save the summary.' -ForegroundColor Cyan
    }

    # PsPing writes UTF-16 to stdout but plain ANSI to stderr, so the two streams are decoded
    # separately (Start-Process/2>&1 would garble one of them).
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $Exe
    $psi.Arguments              = $psArgs -join ' '
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    $psi.StandardErrorEncoding  = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $tOut = $proc.StandardOutput.ReadLineAsync()
        $tErr = $proc.StandardError.ReadLineAsync()

        # Poll so Ctrl+C is honoured promptly; psping itself receives Ctrl+C from the shared console.
        while ($tOut -or $tErr) {
            $pending = @($tOut, $tErr) | Where-Object { $_ }
            [void][System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]$pending, 250)

            if ($tOut -and $tOut.IsCompleted) {
                $line = $tOut.Result
                if ($null -eq $line) { $tOut = $null } else { $tOut = $proc.StandardOutput.ReadLineAsync() }
                if ($line -and $line.Trim()) { Invoke-ProbeLine $line.TrimEnd() }
            }
            if ($tErr -and $tErr.IsCompleted) {
                $line = $tErr.Result
                if ($null -eq $line) { $tErr = $null } else { $tErr = $proc.StandardError.ReadLineAsync() }
                if ($line -and $line.Trim()) { Invoke-ProbeLine $line.TrimEnd() }
            }
        }
        $proc.WaitForExit()
    }
    finally {
        # Runs on normal completion and on Ctrl+C.
        if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
        Write-Summary
        Write-Host "Log saved to: $LogFile" -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------- main
$exe = Find-PsPing -Path $PsPingPath
if (-not $exe) {
    Write-Host 'PsPing (Sysinternals) was not found on this machine.' -ForegroundColor Yellow
    Write-Host 'This script cannot run without it.' -ForegroundColor Yellow
    if (Read-YesNo 'Download PsPing now and add it to your user PATH?') {
        $exe = Install-PsPing
    }
    if (-not $exe) { throw 'PsPing is required. Install it and run the script again.' }
}
if (-not (Test-Path -LiteralPath $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

Write-Host "Using $exe" -ForegroundColor DarkGray
Write-Host "Local time: $(Get-Stamp)" -ForegroundColor DarkGray

do {
    $restart  = $false
    $ip       = Read-TargetIp
    $protocol = Read-Protocol
    $port     = 0

    if ($protocol -eq 'TCP') {
        $port = Read-TcpPort
        if ($null -eq $port) {
            Write-Host 'Exiting without running a probe.'
            break
        }
        if ($port -eq -1) { $restart = $true; continue }
    }

    $count = Read-PacketCount
    $live  = Read-OutputMode

    $safeIp  = $ip.ToString() -replace '[:\.]', '_'
    $suffix  = if ($protocol -eq 'TCP') { "tcp$port" } else { 'icmp' }
    $logFile = Join-Path $LogDirectory ("psping_{0}_{1}_{2}.txt" -f $safeIp, $suffix, (Get-Date -Format 'yyyyMMdd_HHmmss'))

    Invoke-Probe -Exe $exe -Ip $ip -Protocol $protocol -Port $port -Count $count -Live $live -LogFile $logFile

    $restart = Read-YesNo 'Run another probe?'
} while ($restart)

Write-Host 'Done.'
