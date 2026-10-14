#!/bin/bash
#
# invoke-npingprobe.sh - macOS counterpart of Invoke-PsPingProbe.ps1
#
# Interactive wrapper around nping (from the Nmap project) for finding network drops
# over ICMP, TCP or UDP. Every line is stamped with this Mac's local date/time and saved
# to a .txt file. Failed probes are tagged [DROP]; runs of consecutive drops are logged as
# outages (start, end, duration). A summary is always written, also after Ctrl+C.
#
# UDP offers two payloads: a real DNS query (works against any DNS server, e.g. 8.8.8.8 port 53)
# or an empty 32-byte datagram (only meaningful if the target replies to it).
#
# Prompts: target IP -> probe type (TCP/ICMP/UDP) -> port (TCP/UDP) -> packets
#          (5 / custom / continuous) -> output (live / quiet) -> save folder (Enter = default).
#
# If nping is missing the script says exactly which package it will install and asks first.
# ICMP and UDP probes use raw sockets, which need root on macOS; the script checks your
# access and asks for your Mac password (sudo) only when the chosen probe needs it.
#
# Usage:  ./invoke-npingprobe.sh [-i seconds] [-l log_folder] [-h]
#
# Written for the macOS system bash (3.2): no associative arrays, namerefs or ${var,,}.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_LOG_DIR="$SCRIPT_DIR/logs"
INTERVAL=1
LOG_DIR=""
UDP_MODE=""
# DNS query for example.com (type A, class IN), id 0xBEEF, RD=1 - used as the UDP payload.
DNS_QUERY_HEX="0xbeef01000001000000000000076578616d706c6503636f6d0000010001"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-i seconds] [-l log_folder] [-h]

  -i seconds     Seconds between probes (1-3600, default 1)
  -l log_folder  Save logs here. If omitted you are asked (Enter = $DEFAULT_LOG_DIR)
  -h             Show this help
EOF
}

while getopts "i:l:h" opt; do
    case "$opt" in
        i) INTERVAL="$OPTARG" ;;
        l) LOG_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

case "$INTERVAL" in
    ''|*[!0-9]*) echo "Interval must be a whole number of seconds (1-3600)." >&2; exit 2 ;;
esac
if [ "$INTERVAL" -lt 1 ] || [ "$INTERVAL" -gt 3600 ]; then
    echo "Interval must be between 1 and 3600 seconds." >&2; exit 2
fi

# ------------------------------------------------------------------ output helpers
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYN=$'\033[36m'; C_DIM=$'\033[90m'; C_OFF=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_CYN=''; C_DIM=''; C_OFF=''
fi
say()      { printf '%s\n' "$*"; }
say_warn() { printf '%s%s%s\n' "$C_YEL" "$*" "$C_OFF"; }
say_err()  { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF" >&2; }
say_info() { printf '%s%s%s\n' "$C_CYN" "$*" "$C_OFF"; }
say_ok()   { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF"; }

# Read a line from the user; exit cleanly if input is closed (Ctrl+D).
ask() {  # ask "prompt"  -> REPLY
    if ! IFS= read -r -p "$1" REPLY; then echo; exit 0; fi
    REPLY="$(printf '%s' "$REPLY" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
}

ask_yes_no() {  # ask_yes_no "question"  -> returns 0 for yes, 1 for no
    while true; do
        ask "$1 (Y/N): "
        case "$REPLY" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo])     return 1 ;;
            *) say_warn "Please answer Y or N." ;;
        esac
    done
}

# ------------------------------------------------------------------ privileges
is_root()  { [ "$(id -u)" -eq 0 ]; }
is_admin() { id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx admin; }

# ------------------------------------------------------------------ nping discovery / install
find_nping() {
    local c
    for c in "$(command -v nping 2>/dev/null)" /opt/homebrew/bin/nping /usr/local/bin/nping; do
        if [ -n "$c" ] && [ -x "$c" ]; then NPING="$c"; return 0; fi
    done
    return 1
}

find_brew() {
    local c
    for c in "$(command -v brew 2>/dev/null)" /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [ -n "$c" ] && [ -x "$c" ]; then BREW="$c"; return 0; fi
    done
    return 1
}

install_homebrew() {
    say_info "Package to install : Homebrew (the macOS package manager, https://brew.sh)"
    say_info "Why                : it is needed to install 'nmap', which contains nping."
    if is_root; then
        say_err "Homebrew cannot be installed as root. Run this script as your normal user (without sudo)."
        return 1
    fi
    if ! is_admin; then
        say_err "Your account ($(id -un)) is not a macOS administrator, so Homebrew cannot be installed."
        say_err "Ask IT for admin rights, or ask an admin to install nmap, then run this script again."
        return 1
    fi
    say "The Homebrew installer will ask for your Mac password (sudo) and may install the Xcode Command Line Tools."
    ask_yes_no "Install Homebrew now?" || return 1
    if ! sudo -v; then
        say_err "Could not get administrator access (wrong password or sudo not permitted)."
        return 1
    fi
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || return 1
    find_brew || { for c in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$c" ] && BREW="$c"; done; }
    [ -n "${BREW:-}" ] || { say_err "Homebrew installed but 'brew' was not found."; return 1; }
    eval "$("$BREW" shellenv)"
    return 0
}

install_nping() {
    say_warn "nping was not found on this Mac. This script cannot run without it."
    say_info "Package to install : nmap  (Homebrew formula 'nmap' - it provides the 'nping' command)"
    say_info "Command            : brew install nmap"
    if is_root; then
        say_err "Homebrew refuses to run as root. Run this script as your normal user (without sudo)."
        return 1
    fi
    ask_yes_no "Install the 'nmap' package now?" || return 1

    if ! find_brew; then
        say_warn "Homebrew is not installed, and it is required to install 'nmap'."
        install_homebrew || return 1
    fi

    say_info "Installing package: nmap  (running: $BREW install nmap)"
    "$BREW" install nmap || { say_err "'brew install nmap' failed."; return 1; }
    find_nping || { say_err "nmap installed but nping was not found on PATH."; return 1; }
    say_ok "nping installed at $NPING"
    return 0
}

# ------------------------------------------------------------------ prompts
valid_ipv4() {
    local ip="$1" o
    printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || return 1
    local IFS=.
    for o in $ip; do [ "$o" -le 255 ] || return 1; done
    return 0
}
valid_ipv6() {
    printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$' || return 1
    [ "$(printf '%s' "$1" | tr -cd ':' | wc -c | tr -d ' ')" -ge 2 ]
}

read_target() {
    while true; do
        ask "Enter target IP address: "
        if valid_ipv4 "$REPLY" || valid_ipv6 "$REPLY"; then TARGET="$REPLY"; return; fi
        say_warn "'$REPLY' is not a valid IPv4/IPv6 address."
    done
}

read_protocol() {
    while true; do
        ask "Select probe type: [1] TCP  [2] ICMP  [3] UDP: "
        case "$(printf '%s' "$REPLY" | tr '[:lower:]' '[:upper:]')" in
            1|TCP)  PROTO=TCP;  return ;;
            2|ICMP) PROTO=ICMP; return ;;
            3|UDP)  PROTO=UDP;  return ;;
            *) say_warn "Enter 1/TCP, 2/ICMP or 3/UDP." ;;
        esac
    done
}

# Sets UDP_MODE to DNS or EMPTY.
read_udp_mode() {
    while true; do
        say "UDP test method:"
        say "  [1] DNS query - target is a DNS server (e.g. 8.8.8.8 port 53); a reply counts as OK"
        say "  [2] Empty 32-byte datagram - only meaningful if the target replies to it"
        ask "Select UDP method: "
        case "$REPLY" in
            1) UDP_MODE=DNS;   return ;;
            2) UDP_MODE=EMPTY; return ;;
            *) say_warn "Enter 1 or 2." ;;
        esac
    done
}

# Sets PORT. Returns 0 = ok, 1 = restart the script, 2 = exit.
read_port() {
    ask "Enter $PROTO port (1-65535): "
    case "$REPLY" in
        '') say_warn "No port number was provided." ;;
        *[!0-9]*) say_warn "'$REPLY' is not a valid port." ;;
        *)
            if [ "${#REPLY}" -le 5 ] && [ "$REPLY" -ge 1 ] && [ "$REPLY" -le 65535 ]; then
                PORT="$REPLY"; return 0
            fi
            say_warn "'$REPLY' is not a valid port."
            ;;
    esac
    if ask_yes_no "Restart the script?"; then return 1; fi
    return 2
}

# Sets COUNT (0 = continuous).
read_count() {
    while true; do
        ask "Packets to send: [1] 5 packets  [2] Custom number  [3] Continuous (until Ctrl+C): "
        case "$REPLY" in
            1) COUNT=5; return ;;
            3) COUNT=0; return ;;
            2)
                ask "How many packets? (1-1000000): "
                case "$REPLY" in
                    ''|*[!0-9]*) say_warn "'$REPLY' is not a valid number." ;;
                    *)
                        if [ "${#REPLY}" -le 7 ] && [ "$REPLY" -ge 1 ] && [ "$REPLY" -le 1000000 ]; then COUNT="$REPLY"; return; fi
                        say_warn "'$REPLY' is not a valid number."
                        ;;
                esac
                ;;
            *) say_warn "Enter 1, 2 or 3." ;;
        esac
    done
}

# Sets LIVE (1 = live on screen, 0 = quiet, file only).
read_output_mode() {
    while true; do
        ask "Output: [1] Live on screen  [2] Quiet - save to file only (Ctrl+C to stop and save): "
        case "$REPLY" in
            1) LIVE=1; return ;;
            2) LIVE=0; return ;;
            *) say_warn "Enter 1 or 2." ;;
        esac
    done
}

# Enter = default folder, otherwise the folder typed. Sets LOG_DIR to a writable directory.
read_log_dir() {
    local dir
    while true; do
        ask "Save log to folder (press Enter for default: $DEFAULT_LOG_DIR): "
        dir="${REPLY:-$DEFAULT_LOG_DIR}"
        case "$dir" in "~"|"~/"*) dir="$HOME${dir#\~}" ;; esac
        if mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
            LOG_DIR="$(cd "$dir" && pwd)"; return
        fi
        say_warn "Cannot use '$dir' (cannot create it or no write permission)."
    done
}

# ICMP and UDP use raw packets; macOS only allows that for root. TCP uses a normal connect().
# Sets SUDO to "" or "sudo". Returns 1 if root access could not be obtained.
ensure_privileges() {
    SUDO=""
    case "$PROTO" in TCP) return 0 ;; esac
    is_root && return 0
    say_info "$PROTO probes use raw sockets, which require root on macOS."
    if ! is_admin; then
        say_warn "Your account ($(id -un)) is not a macOS administrator, so sudo will probably be refused."
    fi
    say "You will be asked for your Mac password (sudo)."
    if sudo -v; then SUDO="sudo"; return 0; fi
    say_err "Could not get root access. ICMP/UDP need it; a TCP probe does not."
    return 1
}

# ------------------------------------------------------------------ log filter (perl ships with macOS)
# Reads nping output on stdin; stamps lines with local time, tags drops, tracks outages, writes the
# summary. nping prints one SENT line and (if answered) one RCVD line per probe; a SENT with no RCVD
# before the next SENT is a drop.
read -r -d '' PERL_FILTER <<'PERL_EOF' || true
use strict; use warnings;
use Time::HiRes qw(gettimeofday time);
use POSIX qw(strftime);
$| = 1;
my ($logfile, $live, $proto) = @ARGV;
my $interrupted = 0;
$SIG{INT} = sub { $interrupted = 1 };
$SIG{TERM} = sub { $interrupted = 1 };
open(my $LOG, '>>', $logfile) or die "Cannot open $logfile: $!\n";
{ my $old = select($LOG); $| = 1; select($old); }
my $tty = -t STDOUT;
my %COL = (red => "\e[31m", green => "\e[32m", cyan => "\e[36m", yellow => "\e[33m");

sub stamp {
    my ($s, $us) = gettimeofday;
    my $z = strftime('%z', localtime($s));
    $z =~ s/(\d\d)(\d\d)$/$1:$2/;
    return strftime('%Y-%m-%d %H:%M:%S', localtime($s)) . sprintf('.%03d', $us / 1000) . " $z";
}
sub hms { return strftime('%Y-%m-%d %H:%M:%S', localtime($_[0])) }
sub out {
    my ($text, $color, $force) = @_;
    my $e = '[' . stamp() . "] $text";
    print $LOG "$e\n";
    if ($live || $force) {
        if ($color && $tty) { print STDOUT $COL{$color} . $e . "\e[0m\n" } else { print STDOUT "$e\n" }
    }
}

my $FAIL = qr/unreachable|refused|reset|\bRST\b|failed|exceeded|expired|prohibited|no route|timed out|error/i;
my ($ok, $lost, $seq) = (0, 0, 0);
my ($pending, $ostart, $olost);
my @outages;
my $t0 = time;

sub close_outage {
    my ($atend) = @_;
    return unless defined $ostart;
    my $end = time;
    my $secs = sprintf('%.1f', $end - $ostart);
    push @outages, { start => hms($ostart), end => hms($end), lost => $olost, secs => $secs };
    if ($atend) {
        out("[OUTAGE ONGOING AT END] Began " . hms($ostart) . ", $olost probe(s) lost, ~${secs}s, no recovery before the run ended.", 'red', 1);
    } else {
        out("[RECOVERED] Connectivity restored. Outage began " . hms($ostart) . ", $olost probe(s) lost, ~${secs}s.", 'green', 1);
    }
    undef $ostart; $olost = 0;
}
sub record_drop {
    my ($p, $reason, $when) = @_;
    $lost++;
    if (!defined $ostart) { $ostart = $when; $olost = 0 }
    $olost++;
    out("[DROP] #$p->{seq} $reason", 'red', 1);
}

out($ENV{NP_HEADER}, 'cyan', 1);
out('Command: ' . $ENV{NP_CMD}, undef, 0);

while (my $line = <STDIN>) {
    $line =~ s/\r?\n$//;
    next unless $line =~ /\S/;
    if ($line =~ /^SENT \((\d+(?:\.\d+)?)s\)/) {
        if ($pending) {
            my $p = $pending; undef $pending;
            record_drop($p, "no reply (probe sent $p->{wall})", $p->{epoch});
        }
        $seq++;
        $pending = { t => $1, epoch => time, wall => stamp(), seq => $seq };
        next;
    }
    if ($line =~ /^RCVD \((\d+(?:\.\d+)?)s\)/) {
        my $t = $1;
        if ($pending) {
            my $p = $pending; undef $pending;
            my $short = length($line) > 170 ? substr($line, 0, 170) . '...' : $line;
            if ($line =~ $FAIL) {
                record_drop($p, $short, time);
            } else {
                $ok++;
                close_outage(0);
                out(sprintf('OK   #%d  rtt=%.2f ms  | %s', $p->{seq}, ($t - $p->{t}) * 1000, $short));
            }
        } else {
            out($line);
        }
        next;
    }
    out($line);
}

# nping finished on its own: an unanswered last probe is a drop. After Ctrl+C it is unknown, so skip it.
if ($pending && !$interrupted) {
    my $p = $pending; undef $pending;
    record_drop($p, "no reply (probe sent $p->{wall})", $p->{epoch});
}
close_outage(1);

my $total = $ok + $lost;
my $pct = $total ? sprintf('%.2f', 100 * $lost / $total) : '0';
my $dur = int(time - $t0);
out('----------------------------- SUMMARY -----------------------------', 'cyan', 1);
out(sprintf('Started : %s   Ended : %s   Duration : %02d:%02d:%02d', hms($t0), hms(time), $dur / 3600, ($dur % 3600) / 60, $dur % 60), 'cyan', 1);
out("Probes  : $total   Successful : $ok   Dropped : $lost   Loss : $pct%", 'cyan', 1);
if (!@outages) {
    out('Outages : none detected', 'cyan', 1);
} else {
    out('Outages : ' . scalar(@outages), 'yellow', 1);
    out("  - $_->{start} -> $_->{end}  ($_->{lost} lost, ~$_->{secs}s)", 'yellow', 1) for @outages;
}
if ($proto eq 'UDP') {
    out('Note    : UDP has no handshake. A probe counts as OK only if the target answers (a DNS server answers the DNS query); silence or ICMP port unreachable is reported as a drop.', 'cyan', 1);
}
out('-------------------------------------------------------------------', 'cyan', 1);
close($LOG);
exit($interrupted ? 130 : 0);
PERL_EOF

# ------------------------------------------------------------------ run one probe
run_probe() {
    local safe_ip suffix logfile target_args count_label interval_label
    safe_ip="$(printf '%s' "$TARGET" | tr ':.' '__')"
    case "$PROTO" in
        ICMP) suffix="icmp" ;;
        TCP)  suffix="tcp$PORT" ;;
        UDP)  suffix="udp$PORT" ;;
    esac
    logfile="$LOG_DIR/nping_${safe_ip}_${suffix}_$(date '+%Y%m%d_%H%M%S').txt"

    NP_ARGS=()
    case "$PROTO" in
        TCP)  NP_ARGS+=(--tcp-connect -p "$PORT") ;;
        ICMP) NP_ARGS+=(--icmp) ;;
        UDP)
            if [ "$UDP_MODE" = "DNS" ]; then
                # DNS query for example.com A (id 0xBEEF, recursion desired), sent as the UDP payload
                NP_ARGS+=(--udp -p "$PORT" --data "$DNS_QUERY_HEX")
            else
                NP_ARGS+=(--udp -p "$PORT" --data-length 32)
            fi
            ;;
    esac
    case "$TARGET" in *:*) NP_ARGS+=(-6) ;; esac
    NP_ARGS+=(-c "$COUNT" --delay "${INTERVAL}s" "$TARGET")

    if [ "$COUNT" -eq 0 ]; then count_label="continuous"; else count_label="$COUNT"; fi
    if [ "$PROTO" = "ICMP" ]; then dest="$TARGET"; else dest="$TARGET:$PORT"; fi
    type_label="$PROTO"
    if [ "$PROTO" = "UDP" ]; then
        if [ "$UDP_MODE" = "DNS" ]; then type_label="UDP (DNS query)"; else type_label="UDP (empty datagram)"; fi
    fi
    export NP_HEADER="===== Probe started | Host: $(hostname 2>/dev/null | cut -d. -f1) | Type: $type_label | Target: $dest | Packets: $count_label | Interval: ${INTERVAL}s ====="
    export NP_CMD="${SUDO:+$SUDO }$(basename "$NPING") ${NP_ARGS[*]}"

    if [ "$LIVE" -eq 0 ]; then
        say_info "Quiet mode: writing to $logfile"
        say_info "Only drops/recoveries are shown here. Press Ctrl+C to stop and save the summary."
    elif [ "$COUNT" -eq 0 ]; then
        say_info "Press Ctrl+C to stop and save the summary."
    fi

    # Keep this script alive on Ctrl+C so the summary and "log saved" lines still run; nping and the
    # perl filter receive the signal themselves.
    trap ':' INT
    $SUDO "$NPING" "${NP_ARGS[@]}" 2>&1 | perl -e "$PERL_FILTER" -- "$logfile" "$LIVE" "$PROTO"
    local status="${PIPESTATUS[1]}"
    trap - INT

    say_info "Log saved to: $logfile"
    return "$status"
}

# ------------------------------------------------------------------ main
if [ "$(uname -s)" != "Darwin" ]; then
    say_warn "This script is written for macOS; continuing anyway on $(uname -s)."
fi

if ! find_nping; then
    install_nping || { say_err "nping is required. Install it (brew install nmap) and run the script again."; exit 1; }
fi
command -v perl >/dev/null 2>&1 || { say_err "perl was not found (it normally ships with macOS)."; exit 1; }

printf '%sUsing %s%s\n' "$C_DIM" "$NPING" "$C_OFF"
printf '%sLocal time: %s%s\n' "$C_DIM" "$(date '+%Y-%m-%d %H:%M:%S %z')" "$C_OFF"

while true; do
    read_target
    read_protocol
    UDP_MODE=""
    if [ "$PROTO" = "UDP" ]; then read_udp_mode; fi

    PORT=0
    if [ "$PROTO" != "ICMP" ]; then
        read_port; rc=$?
        if [ "$rc" -eq 1 ]; then continue; fi
        if [ "$rc" -eq 2 ]; then say "Exiting without running a probe."; break; fi
    fi

    read_count
    read_output_mode
    [ -n "$LOG_DIR" ] || read_log_dir
    mkdir -p "$LOG_DIR" 2>/dev/null

    if ! ensure_privileges; then
        if ask_yes_no "Restart the script?"; then continue; fi
        break
    fi

    run_probe; status=$?
    if [ "$status" -eq 130 ]; then break; fi   # stopped with Ctrl+C

    ask_yes_no "Run another probe?" || break
done

say "Done."
