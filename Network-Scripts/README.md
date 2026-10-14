# Network drop probe (Windows and macOS)

Interactive scripts that probe one IP over **ICMP**, **TCP** or **UDP**, stamp every result with the
**local time of your machine**, and save it to a `.txt` file, so you can find network drops and when they happened.

| OS      | Script                    | Uses                                                        |
|---------|---------------------------|-------------------------------------------------------------|
| Windows | `Invoke-PsPingProbe.ps1`  | Sysinternals **PsPing**                                     |
| macOS   | `invoke-npingprobe.sh`    | **nping** (from the Nmap project, installed as `nmap`)      |

Both scripts ask the same questions in the same order and write the same style of log.

## Prompts (both scripts)

1. **Target IP**: IPv4 or IPv6, validated.
2. **Probe type**: `1` TCP, `2` ICMP, `3` UDP.
   For UDP you then pick the method: `1` **DNS query** (recommended; see [UDP notes](#udp-notes)) or `2` PsPing latency test (Windows) / empty datagram (macOS).
3. **Port** (TCP and UDP only): 1-65535.
   If the port is blank or invalid you are asked **"Restart the script? (Y/N)"**.
   Yes starts again from the IP prompt. No exits without probing.
4. **Packets to send**: `1` 5 packets, `2` custom number, `3` continuous (until Ctrl+C).
   (The Windows PsPing UDP latency test does not offer continuous, see [UDP notes](#udp-notes).)
5. **Output**: `1` live on screen, or `2` quiet (file only).
6. **Save location**: press **Enter** for the default folder (`logs` next to the script), or type a folder path.
   The folder is created if needed and checked for write access.
7. After a finite run: **"Run another probe? (Y/N)"**.

Optional switches skip prompts: Windows `-Interval`, `-PsPingPath`, `-LogDirectory`; macOS `-i`, `-l`.

### Quiet mode and Ctrl+C

Quiet mode writes everything to the log file. The console shows only `[DROP]`, `[RECOVERED]` and
`[OUTAGE ONGOING AT END]` events, so you can leave it running in a window for hours.
Press **Ctrl+C** at any time (live or quiet): the probe stops, the summary is written and the log file is saved.

> Quiet mode runs in the terminal window you started it in; it is not a detached service.
> To keep it running after you log off, run it from a persistent session (for example a scheduled task or `launchd` job).

---

## Windows: `Invoke-PsPingProbe.ps1`

Requires Windows PowerShell 5.1 or PowerShell 7+ and **Sysinternals PsPing** (`psping.exe` or `psping64.exe`).
**The script cannot run without PsPing.**

```powershell
.\Invoke-PsPingProbe.ps1
.\Invoke-PsPingProbe.ps1 -Interval 2
.\Invoke-PsPingProbe.ps1 -PsPingPath C:\PSTools\psping64.exe -LogDirectory D:\netlogs
```

| Parameter       | Default                   | Purpose                                         |
|-----------------|---------------------------|-------------------------------------------------|
| `-Interval`     | `1`                       | Seconds between probes (1-3600; TCP/ICMP only)  |
| `-PsPingPath`   | auto-detect               | Full path to `psping.exe` / `psping64.exe`      |
| `-LogDirectory` | asks (Enter = `.\logs`)   | Where the `.txt` files are written              |

### PsPing check and automatic install

On every start the script looks for PsPing in this order: the `-PsPingPath` path, the script's own folder, your `PATH`.
If it is not found, the script warns you that it is required and asks
**"Download PsPing now and add it to your user PATH? (Y/N)"**

- **Yes**:
  1. Downloads `psping64.exe` (or `psping.exe` on 32-bit Windows) from `https://live.sysinternals.com`.
  2. Verifies the file has a valid **Microsoft digital signature**. If not, it is discarded.
  3. Installs it to `%LOCALAPPDATA%\PsPing`.
  4. Adds that folder to your **user** `PATH` (no admin rights needed) and to the current session.
  5. Carries on with the probe, with no restart needed.
- **No**: the script exits, since it cannot work without PsPing.

If the download is blocked by a proxy or firewall, get PsPing from
<https://learn.microsoft.com/sysinternals/downloads/psping> and place it next to the script.
`-accepteula` is passed automatically.

---

## macOS: `invoke-npingprobe.sh`

Requires macOS with the system `bash` and `perl` (both ship with macOS) and **nping**.

```bash
chmod +x invoke-npingprobe.sh      # once
./invoke-npingprobe.sh
./invoke-npingprobe.sh -i 2 -l ~/Documents/netlogs
```

| Switch | Default                 | Purpose                                       |
|--------|-------------------------|-----------------------------------------------|
| `-i`   | `1`                     | Seconds between probes (1-3600)               |
| `-l`   | asks (Enter = `./logs`) | Where the `.txt` files are written            |
| `-h`   |                         | Show help                                     |

### nping check and automatic install

If `nping` is not found, the script **names the package before doing anything**:

```
nping was not found on this Mac. This script cannot run without it.
Package to install : nmap  (Homebrew formula 'nmap' - it provides the 'nping' command)
Command            : brew install nmap
Install the 'nmap' package now? (Y/N):
```

- It checks that you are **not running as root** (Homebrew refuses to) and, if Homebrew itself is missing, says so:
  `Package to install : Homebrew (the macOS package manager, https://brew.sh)`. It then checks that your account is a
  macOS **administrator**, asks for confirmation, and validates your **Mac password (sudo)** before running the official Homebrew installer.
- It then runs `brew install nmap` and confirms where `nping` was installed.
- If you answer **No**, or your account is not an administrator, it exits with instructions.

### When root is needed

| Probe | Needs root? | Why |
|-------|-------------|-----|
| TCP   | No          | Uses a normal `connect()` (`nping --tcp-connect`) |
| ICMP  | **Yes**     | Raw sockets |
| UDP   | **Yes**     | Raw packets, so ICMP "port unreachable" replies are seen |

Only for ICMP/UDP does the script explain why, check whether your account is an administrator, and prompt for your
Mac password (`sudo`). If root cannot be obtained it offers to restart, since TCP still works without it.

---

## Example run

The screenshots below were taken with the Windows script: a continuous TCP probe to `8.8.8.8:443` in quiet mode, stopped with Ctrl+C.
The macOS script produces the same log layout.

### Step 1: Answer the prompts

Start the script and answer the prompts: target IP, probe type (`1` TCP), port (`443`), packets (`3` continuous) and output
(`2` quiet). The console confirms the log file path and tells you to press **Ctrl+C** to stop. In quiet mode nothing more is
printed unless a drop occurs.

![Step 1: prompts and quiet mode start](images/01-prompts-quiet-mode.png)

### Step 2: The log file fills in while it runs

Open the `.txt` file from the `logs` folder at any time, even while the script is running. It starts with the header (host,
probe type, target, packets, interval) and the exact command. Each probe then gets its own local timestamp and latency.

![Step 2: log file while the probe is running](images/02-log-file-live.png)

### Step 3: Press Ctrl+C and read the summary

When you press Ctrl+C, the probe stops and the log is closed with the **SUMMARY** block:
start and end time, duration, probes sent, successes, drops, loss % and any outages. Here: 42 probes, 0 dropped, no outages.

![Step 3: summary after Ctrl+C](images/03-summary-after-ctrl-c.png)

If a drop had occurred, you would see `[DROP]` lines with timestamps in the log, and the outage start and end times in the summary.

---

## UDP notes

UDP has no handshake, so a probe is only useful if the target **answers**. Both scripts therefore offer a **DNS query** method:
they send a real DNS query (`example.com`, type A) over UDP and count the reply. Any DNS server answers, so it works against
public resolvers (for example `8.8.8.8` port `53`) or your own DNS servers.

| | Windows | macOS |
|---|---|---|
| **DNS query** (recommended) | Built into the script (no PsPing needed for this). Reply timeout 2 s. | `nping --udp --data <DNS query>` |
| Other method | PsPing latency test (`psping -u -l ...`) | Empty 32-byte datagram |
| Per-probe timestamps, `[DROP]`, outages | **Yes** for DNS query | Yes |
| Continuous mode | Yes for DNS query | Yes |

How results are classified (DNS query method):
- **OK**: a DNS reply arrives (any response code, including `NXDOMAIN`/`REFUSED`; the server is up). The log shows the RTT and response code.
- **`[DROP]` no reply**: nothing came back within 2 s (Windows) or before the next probe (macOS).
- **`[DROP]` ICMP port unreachable**: the host is up but nothing listens on that UDP port.

### PsPing's own UDP mode (Windows, method 2)

PsPing supports UDP, but **only as a latency test against a machine running a PsPing server**:
on the target run `psping -s <ip>:<port>` and allow that UDP port through its firewall. Things to know:

- `-u` is only honoured together with `-l <size>`. `psping -u -n 5 8.8.8.8:53` silently runs a **TCP** ping (the output says `TCP connect to`),
  and `psping -u -l 32 ... 8.8.8.8:53` fails because 8.8.8.8 is not a PsPing server (`Sent = 0`, "Connected" only means the local UDP socket was created).
- It reports **aggregate** statistics, not one line per packet, so there are **no per-drop timestamps**.
- It needs a fixed packet count, so **continuous mode is not offered** for it.
- A PsPing server and nping do **not** talk to each other.

---

## What gets logged

Every line is prefixed with the **local time of the machine running the script**, including milliseconds and UTC offset:

```
[2026-10-14 11:42:24.504 +05:30] [DROP] The remote computer refused the network connection.
[2026-10-14 11:42:31.210 +05:30] [RECOVERED] Connectivity restored. Outage began 2026-10-14 11:42:24, 7 probe(s) lost, ~7.0s.
```

- `[DROP]` marks a failed probe (timeout, unreachable, refused, no reply, etc.).
- Consecutive drops are grouped into an **outage** with start time, end time, probes lost and duration.
- A **SUMMARY** block at the end gives total probes, successes, drops, loss % and the outage list.
- The header records the computer name, probe type, target, packet count and interval, plus the exact command.

Output is plain text (`.txt`), one file per run:

| OS      | File name                                                         |
|---------|-------------------------------------------------------------------|
| Windows | `psping_<ip>_<tcpPORT\|udpPORT\|icmp>_<yyyyMMdd_HHmmss>.txt`      |
| macOS   | `nping_<ip>_<tcpPORT\|udpPORT\|icmp>_<yyyyMMdd_HHmmss>.txt`       |

## How it behaves

- **Windows:** warm-up is disabled (`-w 0`) so every attempt counts, including the first.
- A **closed TCP port counts as a drop** (connection refused). Use a port you know is listening.
- Outage duration is measured by this machine's clock, from the first failed probe to the first success after it.
- **macOS:** nping prints no line for a lost probe, so a probe is declared dropped when the next one is sent without a
  reply to the previous one. A drop therefore appears about one interval late; its log entry shows the time the probe was actually sent.
- A drop against a long timeout can take several seconds to appear (about 5 s for PsPing ICMP).
- ICMP may be blocked by firewalls or deprioritised by routers. If ICMP shows drops but TCP does not, the path is probably filtering ICMP.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Windows: auto-download fails | Check internet/proxy access to `live.sysinternals.com`, or install PsPing manually and use `-PsPingPath` |
| Windows: script blocked by execution policy | `powershell -ExecutionPolicy Bypass -File .\Invoke-PsPingProbe.ps1` |
| macOS: `Permission denied` running the script | `chmod +x invoke-npingprobe.sh`, or run `bash invoke-npingprobe.sh` |
| macOS: install refused | Your account must be a macOS administrator, and the script must not be run with `sudo` |
| macOS: ICMP/UDP asks for a password | Expected; raw sockets need root. TCP does not |
| ICMP shows 100% loss but host is up | Target or a firewall is dropping ICMP; test TCP instead |
| UDP shows no results | Use the **DNS query** method against a DNS server (port 53). The PsPing method needs `psping -s` on the target; see [UDP notes](#udp-notes) |
| Probes to a public IP show 0.3-1 ms or answer on impossible IPs | A VPN, proxy or firewall on your network is answering locally. Test a target behind the link you care about |
