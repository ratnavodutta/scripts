<#
.SYNOPSIS
    Interactive wrapper around Sysinternals PsPing for finding network drops (TCP, ICMP or UDP).

.DESCRIPTION
    Prompts for:
      1. Target IP address
      2. Probe type  - TCP or UDP (both ask for a port) or ICMP
      3. Packet count - 5 packets, a custom number, or continuous (until Ctrl+C; TCP/ICMP only)
      4. Output mode - live on screen, or quiet (file only; Ctrl+C stops and finalises the log)
      5. Save location - Enter for the default folder, or type a folder path

    UDP offers two methods:
      1. DNS query - the script itself sends a real DNS query (example.com A) over UDP once per
         interval and waits 2 s for the reply. Works against any DNS server (e.g. 8.8.8.8 port 53),
         with per-probe timestamps, drops and outages like TCP/ICMP.
      2. PsPing latency test - needs a PsPing server on the target (psping -s <ip>:<port>) and
         gives aggregate statistics only, not one line per packet.

    Every line is stamped with the local date/time of this machine and written to a log
    file. Failed probes (timeouts, unreachable, refused...) are tagged [DROP], and runs of
    consecutive drops are logged as outages with start time, end time and duration.
    A summary is always written, including when the run is stopped with Ctrl+C.

    If TCP/UDP is chosen and no valid port is given, the user is asked whether to restart.

.PARAMETER Interval
    Seconds between probes (default 1).

.PARAMETER PsPingPath
    Optional full path to psping.exe / psping64.exe. If omitted, the script looks in the
    script folder and then in PATH. If PsPing is not found the user is offered an automatic
    download (Sysinternals Live) into %LOCALAPPDATA%\PsPing, added to the user PATH.

.PARAMETER LogDirectory
    Folder for the .txt log files. If omitted, the script asks (Enter = .\logs next to the script).

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
$DefaultLogDirectory = Join-Path $ScriptDir 'logs'

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
        $choice = (Read-Host 'Select probe type: [1] TCP  [2] ICMP  [3] UDP').Trim().ToUpper()
        switch ($choice) {
            { $_ -in '1', 'TCP' }  { return 'TCP' }
            { $_ -in '2', 'ICMP' } { return 'ICMP' }
            { $_ -in '3', 'UDP' }  { return 'UDP' }
            default { Write-Host 'Enter 1/TCP, 2/ICMP or 3/UDP.' -ForegroundColor Yellow }
        }
    }
}

# Returns 'DNS' or 'PSPING'.
function Read-UdpMethod {
    while ($true) {
        Write-Host 'UDP test method:'
        Write-Host '  [1] DNS query - target is a DNS server (e.g. 8.8.8.8 port 53); per-probe timestamps and drops'
        Write-Host '  [2] PsPing latency test - target must be running "psping -s <ip>:<port>"; aggregate results only'
        $choice = (Read-Host 'Select UDP method').Trim()
        switch ($choice) {
            '1' { return 'DNS' }
            '2' { return 'PSPING' }
            default { Write-Host 'Enter 1 or 2.' -ForegroundColor Yellow }
        }
    }
}

# Returns a port number, -1 to restart the script, or $null to exit.
function Read-Port {
    param([string]$Protocol = 'TCP')
    $text = (Read-Host "Enter $Protocol port (1-65535)").Trim()
    $port = 0
    if ($text -and [int]::TryParse($text, [ref]$port) -and $port -ge 1 -and $port -le 65535) { return $port }

    if ($text) { Write-Host "'$text' is not a valid port." -ForegroundColor Yellow }
    else       { Write-Host 'No port number was provided.' -ForegroundColor Yellow }

    if (Read-YesNo 'Restart the script?') { return -1 }
    return $null
}

# Returns 0 for continuous, otherwise the packet count.
function Read-PacketCount {
    param([switch]$NoContinuous)   # PsPing's UDP test needs a fixed count
    $menu = 'Packets to send: [1] 5 packets  [2] Custom number  [3] Continuous (until Ctrl+C)'
    if ($NoContinuous) { $menu = 'Packets to send: [1] 5 packets  [2] Custom number  (continuous is not available for UDP)' }
    while ($true) {
        $choice = (Read-Host $menu).Trim()
        switch ($choice) {
            '1' { return 5 }
            '3' {
                if ($NoContinuous) { Write-Host 'Continuous mode is not supported for UDP. Enter 1 or 2.' -ForegroundColor Yellow }
                else { return 0 }
            }
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

# Enter = default folder; otherwise the typed folder. Returns a usable, writable directory.
function Read-LogDirectory {
    param([string]$Default)
    while ($true) {
        $text = (Read-Host "Save log to folder (press Enter for default: $Default)").Trim().Trim('"')
        $dir  = if ($text) { $text } else { $Default }
        try {
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $full  = (Resolve-Path -LiteralPath $dir).Path
            $probe = Join-Path $full ('.write_test_{0}' -f [guid]::NewGuid().ToString('N'))
            New-Item -ItemType File -Path $probe -Force | Out-Null
            Remove-Item -LiteralPath $probe -Force
            return $full
        }
        catch {
            Write-Host "Cannot use '$dir': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------- probe engine
$script:DropPattern = '(?i)timed out|unreachable|more data is available|could not connect|refused|no route|general failure|ttl expired|failed|error|unknown host|could not (find|resolve)'
$script:OkPattern   = '(?i)^\s*(Reply from|Connecting to).*:\s*[\d.,]+\s*ms\s*$'
$script:SkipPattern = '(?i)^\s*(Sent\b|Minimum\b|Approximate\b|Ping statistics|TCP (connect|ping)|Latency|Error (pinging|connecting)|UDP (latency|roundtrip))'

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

function Register-Drop {
    param([string]$Text)
    $script:Lost++
    if ($null -eq $script:OutageStart) {
        $script:OutageStart = Get-Date
        $script:OutageLost  = 0
    }
    $script:OutageLost++
    Write-Quiet "[DROP] $Text" 'Red'
}

function Register-Ok {
    param([string]$Text)
    $script:Ok++
    Close-Outage
    Write-Quiet $Text
}

function Invoke-ProbeLine {
    param([string]$Line)

    # UDP latency test prints progress percentages (repeated lines); keep them out of the log.
    if ($script:Protocol -eq 'UDP' -and $Line -match '\d+%\s*$') { return }
    if ($script:Protocol -eq 'UDP' -and $Line -match 'Sent = (\d+), Size') { $script:Ok += [int]$Matches[1] }
    # UDP has no connection: PsPing prints "Connected" as soon as its local socket exists.
    if ($script:Protocol -eq 'UDP' -and $Line -match '^\s*Connected\s*$') { return }

    if ($Line -notmatch $script:SkipPattern -and $Line -match $script:DropPattern) {
        Register-Drop $Line
        return
    }
    if ($Line -match $script:OkPattern) {
        Register-Ok $Line
        return
    }
    Write-Quiet $Line
}

# ---------------------------------------------------------------- UDP DNS probe (no PsPing needed)
function New-DnsQuery {
    param([int]$Id, [string]$Name = 'example.com')
    $b = New-Object System.Collections.Generic.List[byte]
    $hi = [byte](($Id -shr 8) -band 255)
    $lo = [byte]($Id -band 255)
    $b.AddRange([byte[]]@($hi, $lo, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))   # header: RD=1, 1 question
    foreach ($label in $Name.Split('.')) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        $b.Add([byte]$bytes.Length)
        $b.AddRange($bytes)
    }
    $b.AddRange([byte[]]@(0, 0, 1, 0, 1))                                                              # root, QTYPE=A, QCLASS=IN
    return ,$b.ToArray()
}

function Invoke-DnsUdpLoop {
    param([System.Net.IPAddress]$Ip, [int]$Port, [int]$Count)

    $timeoutMs = 2000
    $rcodes    = @{ 0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'; 4 = 'NOTIMP'; 5 = 'REFUSED' }
    $client    = New-Object System.Net.Sockets.UdpClient($Ip.AddressFamily)
    try {
        # A connected UDP socket lets Windows report ICMP "port unreachable" as WSAECONNRESET.
        $client.Connect($Ip, $Port)
        $seq = 0
        while ($Count -eq 0 -or $seq -lt $Count) {
            $seq++
            $id    = Get-Random -Minimum 1 -Maximum 65535
            $query = New-DnsQuery -Id $id
            $tick  = [System.Diagnostics.Stopwatch]::StartNew()
            $reply = $null
            $why   = $null
            try {
                [void]$client.Send($query, $query.Length)
                $ep = New-Object System.Net.IPEndPoint($Ip, $Port)
                while ($null -eq $reply -and $tick.ElapsedMilliseconds -lt $timeoutMs) {
                    $client.Client.ReceiveTimeout = [Math]::Max(1, $timeoutMs - [int]$tick.ElapsedMilliseconds)
                    $data = $client.Receive([ref]$ep)
                    # ignore late replies to earlier probes: match the query ID and the QR (response) bit
                    if ($data.Length -ge 12 -and $data[0] -eq (($id -shr 8) -band 255) -and $data[1] -eq ($id -band 255) -and ($data[2] -band 0x80)) {
                        $reply = $data
                    }
                }
                if ($null -eq $reply) { $why = "no reply within $timeoutMs ms" }
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                $se = $_.Exception
                while ($se -and $se -isnot [System.Net.Sockets.SocketException]) { $se = $se.InnerException }
                if ($se -and $se.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { $why = "no reply within $timeoutMs ms" }
                elseif ($se -and $se.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { $why = 'ICMP port unreachable (nothing is listening on that UDP port)' }
                elseif ($se) { $why = "socket error: $($se.Message)" }
                else { $why = "error: $($_.Exception.Message)" }
            }

            if ($reply) {
                $rc = $rcodes[[int]($reply[3] -band 0x0F)]
                if (-not $rc) { $rc = "RCODE $($reply[3] -band 0x0F)" }
                Register-Ok ("OK   #{0}  rtt={1:N2} ms  | DNS reply from {2}:{3} ({4}, {5} bytes)" -f $seq, $tick.Elapsed.TotalMilliseconds, $Ip, $Port, $rc, $reply.Length)
            } else {
                Register-Drop "#$seq $why"
            }

            if ($Count -eq 0 -or $seq -lt $Count) {
                $wait = ($Interval * 1000) - [int]$tick.ElapsedMilliseconds
                if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
            }
        }
    }
    finally {
        $client.Close()
    }
}

function Write-Summary {
    Close-Outage -AtEnd
    $total = $script:Ok + $script:Lost
    $pct   = if ($total) { [math]::Round(100 * $script:Lost / $total, 2) } else { 0 }
    $run   = (Get-Date) - $script:StartTime

    Write-LogLine '----------------------------- SUMMARY -----------------------------' 'Cyan'
    Write-LogLine ("Started : {0:yyyy-MM-dd HH:mm:ss}   Ended : {1:yyyy-MM-dd HH:mm:ss}   Duration : {2:hh\:mm\:ss}" -f $script:StartTime, (Get-Date), $run) 'Cyan'
    if ($script:Protocol -eq 'UDP' -and -not $script:UdpDns) {
        Write-LogLine "UDP     : $($script:Ok) datagram(s) completed by PsPing   Errors : $($script:Lost)" 'Cyan'
        if ($script:Ok -eq 0) {
            Write-LogLine 'Result  : FAILED - PsPing completed 0 UDP round trips.' 'Yellow'
            Write-LogLine '          PsPing UDP only works against a host running "psping -s <ip>:<port>" (UDP port allowed through firewalls).' 'Yellow'
            Write-LogLine '          Other UDP services (e.g. DNS 8.8.8.8:53) do not answer it. "Connected" only means the local UDP socket was created.' 'Yellow'
        }
        Write-LogLine 'Note    : PsPing UDP reports aggregate latency, not one line per packet, so per-drop timestamps are not available.' 'Cyan'
    } else {
        Write-LogLine "Probes  : $total   Successful : $($script:Ok)   Dropped : $($script:Lost)   Loss : $pct%" 'Cyan'
        if ($script:UdpDns) {
            Write-LogLine 'Note    : UDP DNS probe - a probe is OK when the server replies within 2 s; silence or ICMP port unreachable is a drop.' 'Cyan'
        }
    }
    if ($script:Protocol -eq 'UDP' -and -not $script:UdpDns) {
        # aggregate test only: no per-packet timing, so no outage tracking
    } elseif ($script:Outages.Count -eq 0) {
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
        [string]$LogFile,
        [string]$UdpMode = ''   # UDP only: 'DNS' or 'PSPING'
    )

    $script:LogFile     = $LogFile
    $script:Protocol    = $Protocol
    $script:UdpDns      = ($Protocol -eq 'UDP' -and $UdpMode -eq 'DNS')
    $script:Live        = $Live
    $script:Ok          = 0
    $script:Lost        = 0
    $script:OutageStart = $null
    $script:OutageLost  = 0
    $script:Outages     = New-Object System.Collections.Generic.List[object]
    $script:StartTime   = Get-Date

    $ipText = $Ip.ToString()
    if ($Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $ipText = "[$ipText]" }

    # PsPing: "host" = ICMP ping, "host:port" = TCP connect ping, "-u host:port" = UDP latency test.
    $destination = if ($Protocol -eq 'ICMP') { $ipText } else { "${ipText}:$Port" }
    if ($script:UdpDns) {
        $psArgs = @()
    } elseif ($Protocol -eq 'UDP') {
        # Latency-test mode: fixed count, no interval switch, needs "psping -s" on the target.
        $psArgs = @('-accepteula', '-u', '-l', 32, '-n', $Count, '-w', 0, $destination)
    } else {
        $psArgs = @('-accepteula', '-i', $Interval, '-w', 0)     # -w 0: no warm-up, so every attempt is counted
        $psArgs += if ($Count -eq 0) { '-t' } else { @('-n', $Count) }
        $psArgs += $destination
    }

    $countText = if ($Count -eq 0) { 'continuous' } else { $Count }
    $intervalText = if ($Protocol -eq 'UDP' -and -not $script:UdpDns) { 'n/a' } else { "${Interval}s" }
    $typeText     = if ($script:UdpDns) { 'UDP (DNS query)' } elseif ($Protocol -eq 'UDP') { 'UDP (PsPing latency test)' } else { $Protocol }
    Write-LogLine "===== Probe started | Host: $env:COMPUTERNAME | Type: $typeText | Target: $destination | Packets: $countText | Interval: $intervalText =====" 'Cyan'
    if ($script:UdpDns) {
        Write-LogLine 'Command: built-in UDP DNS probe (query: example.com A, reply timeout: 2000 ms)'
    } else {
        Write-LogLine "Command: $(Split-Path $Exe -Leaf) $($psArgs -join ' ')"
    }
    if (-not $Live) {
        Write-Host "Quiet mode: writing to $LogFile" -ForegroundColor Cyan
        Write-Host 'Only drops/recoveries are shown here. Press Ctrl+C to stop and save the summary.' -ForegroundColor Cyan
    } elseif ($Count -eq 0) {
        Write-Host 'Press Ctrl+C to stop and save the summary.' -ForegroundColor Cyan
    }

    if ($script:UdpDns) {
        try { Invoke-DnsUdpLoop -Ip $Ip -Port $Port -Count $Count }
        finally {
            Write-Summary
            Write-Host "Log saved to: $LogFile" -ForegroundColor Cyan
        }
        return
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
Write-Host "Using $exe" -ForegroundColor DarkGray
Write-Host "Local time: $(Get-Stamp)" -ForegroundColor DarkGray

do {
    $restart  = $false
    $ip       = Read-TargetIp
    $protocol = Read-Protocol
    $udpMode  = ''
    if ($protocol -eq 'UDP') { $udpMode = Read-UdpMethod }
    $port     = 0

    if ($protocol -in 'TCP', 'UDP') {
        $port = Read-Port -Protocol $protocol
        if ($null -eq $port) {
            Write-Host 'Exiting without running a probe.'
            break
        }
        if ($port -eq -1) { $restart = $true; continue }
    }

    $count = if ($udpMode -eq 'PSPING') { Read-PacketCount -NoContinuous } else { Read-PacketCount }
    $live  = Read-OutputMode
    if (-not $LogDirectory) { $LogDirectory = Read-LogDirectory -Default $DefaultLogDirectory }

    $safeIp  = $ip.ToString() -replace '[:\.]', '_'
    $suffix  = if ($protocol -eq 'ICMP') { 'icmp' } else { "$($protocol.ToLower())$port" }
    $logFile = Join-Path $LogDirectory ("psping_{0}_{1}_{2}.txt" -f $safeIp, $suffix, (Get-Date -Format 'yyyyMMdd_HHmmss'))

    Invoke-Probe -Exe $exe -Ip $ip -Protocol $protocol -Port $port -Count $count -Live $live -LogFile $logFile -UdpMode $udpMode

    $restart = Read-YesNo 'Run another probe?'
} while ($restart)

Write-Host 'Done.'
