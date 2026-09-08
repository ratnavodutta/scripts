# Hostname Ping Script

`hostname-ping.ps1` is a standalone Windows PowerShell script for checking
hostnames and IP addresses with ICMP echo requests. It uses the
built-in `Test-Connection` cmdlet and does not require a module, separate
runtime, third-party utility, or system configuration change.

## Usage

Run it from Windows PowerShell:

```powershell
.\hostname-ping.ps1 -InputFile "C:\Ops\hosts.txt"
```

Optional parameters:

```powershell
.\hostname-ping.ps1 `
  -InputFile "C:\Ops\hosts.txt" `
  -OutputFile "C:\Ops\reports\hosts-2026-09-02.csv" `
  -PacketCount 6
```

- `-InputFile` is required and must point to an existing file.
- `-OutputFile` is optional. By default, the script writes
  `hostname-ping-results.csv` next to the input file. The parent directory of
  a requested output path must already exist.
- `-PacketCount` is optional, defaults to `4`, and accepts values from `1`
  through `1000`. That many ICMP requests are attempted for each entry.

## Input file format

Put one hostname or IP address on each line. Leading and trailing whitespace
is removed. Blank lines and comment lines (lines whose first non-whitespace
character is `#`) are ignored. Inline comments are not removed, so an entry
such as `server01 # production` is tested as written.

Example:

```text
# Production servers
 server01.example.com
10.20.30.40

# A host that may be offline
server02.example.com
```

Every remaining line is tested independently. DNS failures, timeouts, and
other errors are recorded in that host's row and do not stop the remaining
hosts from being checked.

## Output

The output is UTF-8 CSV with one row per tested host and these stable columns:

| Column | Description |
| --- | --- |
| `Host` | Trimmed hostname or IP address from the input |
| `Status` | `Success` when at least one reply arrives; otherwise `Failure` |
| `PacketsSent` | Requested packet count |
| `PacketsReceived` | Number of replies received |
| `PacketLossPercent` | Calculated loss percentage, including partial responses |
| `Timestamp` | UTC timestamp for the result, in ISO 8601 format |
| `Detail` | Reply summary or a useful error message |

The console prints the total processed, successful, and failed counts, plus the
results path.

Process exit codes:

- `0`: Results were written and every tested host received at least one reply.
- `1`: Results were written, but one or more hosts failed.
- `2`: The input path is invalid or the input could not be read.
- `3`: The results file could not be written.

An empty or comments-only input file is valid: it produces a header-only CSV
and a successful summary with zero hosts processed.

## Windows PowerShell 5.1 validation

The native smoke test must be run on a Windows jump server before operators
rely on the report. The Linux development environment cannot execute Windows
PowerShell 5.1, so no native Windows result is implied by development checks.
The script was reviewed for Windows PowerShell 5.1 compatibility: it uses only
the built-in `Test-Connection`, `Get-Content`, `Export-Csv`, and `Set-Content`
cmdlets plus syntax supported by Windows PowerShell 5.1. It does not require
PowerShell 7, a module, or a third-party executable.

Run each command from a fresh Windows PowerShell 5.1 prompt. Invoking a child
`powershell.exe` process keeps the script's `exit` statement from closing the
operator's current shell; `$LASTEXITCODE` is then the script's process exit
code.

```powershell
$root = Join-Path $env:TEMP "hostname-ping-smoke"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$script = (Resolve-Path .\hostname-ping.ps1).Path
```

1. **Reachable host and exit code 0**

   ```powershell
   Set-Content -LiteralPath (Join-Path $root "reachable.txt") -Value "localhost"
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
     -InputFile (Join-Path $root "reachable.txt") `
     -OutputFile (Join-Path $root "reachable.csv") `
     -PacketCount 3
   $LASTEXITCODE
   ```

   Expected: exit code `0`; console summary
   `Processed: 1 host(s); Successful: 1; Failed: 0`; one CSV row with
   `Status=Success`, `PacketsSent=3`, `PacketsReceived=3`, and
   `PacketLossPercent=0`. If the jump server blocks ICMP to `localhost`, use
   another host known to reply to ICMP and record that environmental result.

2. **Unreachable host, DNS failure, and continued processing**

   ```powershell
   @(
     "localhost"
     "192.0.2.1"
     "this-host-must-not-exist.invalid"
   ) | Set-Content -LiteralPath (Join-Path $root "mixed.txt")
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
     -InputFile (Join-Path $root "mixed.txt") `
     -OutputFile (Join-Path $root "mixed.csv") `
     -PacketCount 2
   $LASTEXITCODE
   ```

   Expected: exit code `1`; console summary
   `Processed: 3 host(s); Successful: 1; Failed: 2`; three CSV rows in input
   order. The `localhost` row should show `Success`, `PacketsSent=2`,
   `PacketsReceived=2`, and `PacketLossPercent=0`. The unreachable and DNS
   failure rows should show `Failure`, `PacketsSent=2`,
   `PacketsReceived=0`, and `PacketLossPercent=100`, with non-empty
   `Detail` values. Network policy can make the reserved test address behave
   differently; the required checks are that the failure row is recorded and
   the later DNS-failure entry is still tested.

3. **Comments-only input and exact header**

   ```powershell
   @(
     "# comment"
     "   "
     "`t# indented comment"
   ) | Set-Content -LiteralPath (Join-Path $root "comments-only.txt")
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
     -InputFile (Join-Path $root "comments-only.txt") `
     -OutputFile (Join-Path $root "comments-only.csv")
   $LASTEXITCODE
   Get-Content -LiteralPath (Join-Path $root "comments-only.csv")
   ```

   Expected: exit code `0`; console summary
   `Processed: 0 host(s); Successful: 0; Failed: 0`; the output contains
   exactly this one header line and no data rows:

   ```text
   Host,Status,PacketsSent,PacketsReceived,PacketLossPercent,Timestamp,Detail
   ```

4. **Invalid input path and exit code 2**

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
     -InputFile (Join-Path $root "does-not-exist.txt") `
     -OutputFile (Join-Path $root "invalid-input.csv")
   $LASTEXITCODE
   ```

   Expected: a clear read error, exit code `2`, and no results file.

5. **Output write error and exit code 3**

   ```powershell
   $missingParent = Join-Path $root "parent-does-not-exist"
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script `
     -InputFile (Join-Path $root "comments-only.txt") `
     -OutputFile (Join-Path $missingParent "results.csv")
   $LASTEXITCODE
   ```

   Expected: a clear write error, exit code `3`, and no results file.

6. **Packet counts and partial loss**

   Repeat the reachable-host test with `-PacketCount 1` and `-PacketCount 6`.
   Confirm every row's `PacketsSent` equals the selected value. If a host
   returns fewer replies than requested, confirm
   `PacketLossPercent` equals
   `Round((PacketsSent - PacketsReceived) / PacketsSent * 100, 2)` and the
   `Detail` value says the response was partial.
