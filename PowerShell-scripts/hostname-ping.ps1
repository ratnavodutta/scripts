<#
.SYNOPSIS
    Tests a list of hostnames or IP addresses with ICMP echo requests.

.DESCRIPTION
    Reads one hostname or IP address per line, ignoring blank lines and lines
    whose first non-whitespace character is '#'. Each remaining entry is
    tested independently with the built-in Test-Connection cmdlet.

    Exit codes:
      0 - The results file was written and every tested host received a reply.
      1 - The results file was written, but one or more hosts failed.
      2 - Input or command-line validation failed.
      3 - The results file could not be written.

.PARAMETER InputFile
    Path to the text file containing hostnames or IP addresses.

.PARAMETER OutputFile
    Optional path for the CSV results file. Defaults to
    hostname-ping-results.csv next to InputFile.

.PARAMETER PacketCount
    Number of ICMP echo requests sent to each host. Defaults to 4.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000)]
    [int]$PacketCount = 4
)

$ErrorActionPreference = "Stop"

function Get-ErrorDetail {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Errors
    )

    $messages = @(
        $Errors |
            Where-Object { $null -ne $_ } |
            ForEach-Object {
                if ($_.Exception -and $_.Exception.Message) {
                    $_.Exception.Message
                } elseif ($_.ToString()) {
                    $_.ToString()
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    if ($messages.Count -eq 0) {
        return "No ICMP reply was received."
    }

    return ($messages -join " | ")
}

try {
    if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
        throw "Input file does not exist or is not a file: $InputFile"
    }

    $resolvedInput = (Resolve-Path -LiteralPath $InputFile -ErrorAction Stop).Path
    $inputDirectory = Split-Path -LiteralPath $resolvedInput -Parent

    if ([string]::IsNullOrWhiteSpace($OutputFile)) {
        $OutputFile = Join-Path -Path $inputDirectory -ChildPath "hostname-ping-results.csv"
    }

    $lines = @(Get-Content -LiteralPath $resolvedInput -ErrorAction Stop)
} catch {
    Write-Error ("Unable to read input file: {0}" -f $_.Exception.Message) -ErrorAction Continue
    exit 2
}

$hosts = @(
    $lines |
        ForEach-Object { $_.Trim() } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")
        }
)

$results = @()
$successfulCount = 0
$failedCount = 0

foreach ($hostEntry in $hosts) {
    $pingErrors = @()
    $detail = ""
    $received = 0

    try {
        $replies = @(Test-Connection -ComputerName $hostEntry `
                -Count $PacketCount `
                -ErrorAction SilentlyContinue `
                -ErrorVariable pingErrors)
        $received = $replies.Count

        if ($received -gt 0) {
            $status = "Success"
            $successfulCount++

            if ($received -lt $PacketCount) {
                $detail = "Partial response; one or more packets timed out."
            } else {
                $detail = "All packets received."
            }
        } else {
            $status = "Failure"
            $failedCount++
            $detail = Get-ErrorDetail -Errors $pingErrors
        }
    } catch {
        $status = "Failure"
        $failedCount++
        $detail = $_.Exception.Message
    }

    $lossPercent = [math]::Round((($PacketCount - $received) / $PacketCount) * 100, 2)

    $results += [pscustomobject][ordered]@{
        Host                = $hostEntry
        Status              = $status
        PacketsSent         = $PacketCount
        PacketsReceived     = $received
        PacketLossPercent   = $lossPercent
        Timestamp           = (Get-Date).ToUniversalTime().ToString("o")
        Detail              = $detail
    }
}

try {
    $outputParent = Split-Path -LiteralPath $OutputFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputParent) -and
        -not (Test-Path -LiteralPath $outputParent -PathType Container)) {
        throw "Output directory does not exist: $outputParent"
    }

    if ($results.Count -eq 0) {
        "Host,Status,PacketsSent,PacketsReceived,PacketLossPercent,Timestamp,Detail" |
            Set-Content -LiteralPath $OutputFile -Encoding UTF8 -Force -ErrorAction Stop
    } else {
        $results | Export-Csv -LiteralPath $OutputFile `
            -NoTypeInformation `
            -Encoding UTF8 `
            -Force `
            -ErrorAction Stop
    }
} catch {
    Write-Error ("Unable to write results file '{0}': {1}" -f $OutputFile, $_.Exception.Message) -ErrorAction Continue
    exit 3
}

Write-Host ("Processed: {0} host(s); Successful: {1}; Failed: {2}" -f `
    $hosts.Count, $successfulCount, $failedCount)
Write-Host ("Results: {0}" -f $OutputFile)

if ($failedCount -gt 0) {
    exit 1
}

exit 0