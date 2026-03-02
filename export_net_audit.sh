#!/usr/bin/env bash

# Exports net_connect audit entries to a user-readable CSV
# Run as root via systemd timer

REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
REAL_HOME=$(eval echo "~$REAL_USER")
OUTFILE="${REAL_HOME}/.golannalog/audit_connections.csv"
mkdir -p "$(dirname "$OUTFILE")"
TMPFILE="${OUTFILE}.tmp"

# Write header if file doesn't exist
if [[ ! -f "$OUTFILE" ]]; then
    echo "timestamp,process,exe,uid,remote_ip,remote_port" > "$OUTFILE"
fi

# Parse raw ausearch output: SOCKADDR comes before SYSCALL per event
ausearch -k net_connect --raw 2>/dev/null | \
awk '
    /^type=SOCKADDR/ {
        ip=""; port=""
        # IPv4: saddr_fam=inet laddr=x.x.x.x lport=NNN
        if (match($0, /saddr_fam=inet laddr=([^ }]+) lport=([^ }]+)/, m)) {
            ip=m[1]; port=m[2]
        }
        # IPv6: saddr_fam=inet6 laddr=xxxx:... lport=NNN
        else if (match($0, /saddr_fam=inet6 laddr=([^ }]+) lport=([^ }]+)/, m)) {
            ip=m[1]; port=m[2]
        }
        # Skip loopback and unresolved
        if (ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "") ip=""
    }
    /^type=SYSCALL/ {
        if (ip == "") next
        ts=""; comm=""; exe=""; uid=""
        match($0, /msg=audit\(([0-9.]+):/, m); ts=m[1]
        match($0, /comm="([^"]+)"/, m); comm=m[1]
        match($0, /exe="([^"]+)"/, m); exe=m[1]
        match($0, / auid=([0-9]+)/, m); uid=m[1]
        if (comm != "" && ip != "") {
            print ts "," comm "," exe "," uid "," ip "," port
        }
        ip=""
    }
' | sort -u > "$TMPFILE"

# Append only new entries
if [[ -s "$OUTFILE" ]]; then
    tail -n +2 "$OUTFILE" | sort -u > "${TMPFILE}.existing"
    comm -13 "${TMPFILE}.existing" "$TMPFILE" >> "$OUTFILE"
    rm -f "${TMPFILE}.existing"
else
    echo "timestamp,process,exe,uid,remote_ip,remote_port" > "$OUTFILE"
    cat "$TMPFILE" >> "$OUTFILE"
fi

rm -f "$TMPFILE"

# Ensure the user can read it
chown "$REAL_USER":"$REAL_USER" "$OUTFILE"
chmod 600 "$OUTFILE"
