#!/usr/bin/env python3
"""
Firewall Monitor Daemon — Kali Linux iptables Project
Watches firewall logs, auto-blocks brute-force IPs,
writes JSON stats for the dashboard.
"""

import os, sys, re, json, time, subprocess, signal, threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

# ─── Config ────────────────────────────────────────────────
LOG_FILE       = "/var/log/firewall/firewall.log"
KERNEL_LOG     = "/var/log/kern.log"
STATS_FILE     = "/var/log/firewall/stats.json"
BLOCKED_IPS    = "/etc/firewall/blocked_ips.txt"
TRUSTED_IPS    = "/etc/firewall/trusted_ips.txt"

BRUTE_THRESHOLD = 5       # auto-block after N blocked hits from same IP
BRUTE_WINDOW    = 60      # seconds
CHECK_INTERVAL  = 3       # seconds between log checks
MAX_RECENT_LOGS = 200     # keep last N log entries in stats

# ─── Patterns ──────────────────────────────────────────────
RE_FW   = re.compile(r'\[FW-(\S+)\].*SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+)(?:.*DPT=(\d+))?')
RE_DATE = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')

THREAT_LABELS = {
    "BLOCKED":    "Blocked Packet",
    "BLOCKED-IP": "Known Bad IP",
    "SSH-BRUTE":  "SSH Brute Force",
    "SYN-FLOOD":  "SYN Flood",
    "NULL-SCAN":  "NULL Scan",
    "XMAS-SCAN":  "XMAS Scan",
    "FIN-SCAN":   "FIN Scan",
}

# ─── State ─────────────────────────────────────────────────
stats = {
    "total_blocked":   0,
    "total_allowed":   0,
    "brute_force":     0,
    "port_scans":      0,
    "syn_floods":      0,
    "unique_attackers":set(),
    "blocked_ips":     [],
    "trusted_ips":     [],
    "recent_logs":     deque(maxlen=MAX_RECENT_LOGS),
    "hourly_counts":   defaultdict(int),
    "top_sources":     defaultdict(int),
    "top_ports":       defaultdict(int),
    "threat_types":    defaultdict(int),
    "last_updated":    "",
    "uptime_start":    datetime.now().isoformat(),
}

ip_hit_times = defaultdict(list)   # IP → list of block timestamps
running = True

# ─── Helpers ───────────────────────────────────────────────
def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception:
        return ""

def load_ip_list(path):
    try:
        return [l.strip() for l in Path(path).read_text().splitlines()
                if l.strip() and not l.startswith('#')]
    except Exception:
        return []

def block_ip(ip):
    run_cmd(f"iptables -I INPUT 1 -s {ip} -j DROP")
    with open(BLOCKED_IPS, 'a') as f:
        f.write(f"{ip}\n")
    log_event("AUTO-BLOCK", ip, "0.0.0.0", None,
              f"Auto-blocked after {BRUTE_THRESHOLD}+ hits in {BRUTE_WINDOW}s")
    print(f"[AUTO-BLOCK] {ip}")

def log_event(tag, src, dst, dpt, note=""):
    entry = {
        "time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type":  THREAT_LABELS.get(tag, tag),
        "src":   src,
        "dst":   dst,
        "port":  dpt or "—",
        "note":  note,
        "color": _threat_color(tag),
    }
    stats["recent_logs"].appendleft(entry)

def _threat_color(tag):
    if "BRUTE" in tag or "FLOOD" in tag: return "red"
    if "SCAN"  in tag:                   return "orange"
    if "BLOCKED-IP" in tag:              return "purple"
    return "yellow"

# ─── Parse log line ────────────────────────────────────────
def parse_line(line):
    m = RE_FW.search(line)
    if not m:
        return
    tag, src, dst, dpt = m.group(1), m.group(2), m.group(3), m.group(4)

    stats["total_blocked"] += 1
    stats["top_sources"][src] += 1
    stats["threat_types"][tag] += 1
    if dpt:
        stats["top_ports"][dpt] += 1

    hour = datetime.now().strftime("%H:00")
    stats["hourly_counts"][hour] += 1

    if "BRUTE" in tag:
        stats["brute_force"] += 1
        stats["unique_attackers"].add(src)
    if "SCAN" in tag:
        stats["port_scans"] += 1
    if "FLOOD" in tag:
        stats["syn_floods"] += 1

    # Track hits per IP for auto-blocking
    now = time.time()
    ip_hit_times[src] = [t for t in ip_hit_times[src]
                          if now - t < BRUTE_WINDOW]
    ip_hit_times[src].append(now)

    if len(ip_hit_times[src]) >= BRUTE_THRESHOLD:
        blocked = load_ip_list(BLOCKED_IPS)
        if src not in blocked:
            block_ip(src)
            ip_hit_times[src] = []

    log_event(tag, src, dst, dpt)

# ─── Tail log file ─────────────────────────────────────────
def tail_log():
    global running
    # Try firewall log first, fall back to kern.log
    log_path = LOG_FILE if Path(LOG_FILE).exists() else KERNEL_LOG
    print(f"[Monitor] Watching: {log_path}")

    try:
        with open(log_path, 'r') as f:
            f.seek(0, 2)   # seek to end
            while running:
                line = f.readline()
                if line:
                    if "[FW-" in line:
                        parse_line(line)
                else:
                    time.sleep(0.5)
    except FileNotFoundError:
        print(f"[Monitor] Log file not found: {log_path}. Using demo mode.")
        demo_mode()

# ─── Demo mode (no root / no log file) ────────────────────
import random

DEMO_IPS   = ["45.33.32.156","185.220.101.9","192.168.1.105",
               "10.0.0.22","203.0.113.42","198.51.100.7"]
DEMO_TAGS  = list(THREAT_LABELS.keys())
DEMO_PORTS = ["22","80","443","3389","8080","21","23"]

def demo_mode():
    global running
    print("[Monitor] Demo mode: generating synthetic events.")
    while running:
        tag = random.choice(DEMO_TAGS)
        src = random.choice(DEMO_IPS)
        dst = "192.168.1.1"
        dpt = random.choice(DEMO_PORTS)
        parse_line(f"Jan  1 00:00:00 kali kernel: [FW-{tag}] "
                   f"IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP DPT={dpt}")
        time.sleep(random.uniform(0.5, 2.5))

# ─── Persist stats to JSON ─────────────────────────────────
def save_stats():
    global running
    while running:
        stats["blocked_ips"]      = load_ip_list(BLOCKED_IPS)
        stats["trusted_ips"]      = load_ip_list(TRUSTED_IPS)
        stats["last_updated"]     = datetime.now().isoformat()
        stats["unique_attackers_count"] = len(stats["unique_attackers"])

        # Build serialisable snapshot
        snapshot = {k: v for k, v in stats.items()}
        snapshot["recent_logs"]        = list(stats["recent_logs"])
        snapshot["hourly_counts"]       = dict(stats["hourly_counts"])
        snapshot["top_sources"]         = dict(
            sorted(stats["top_sources"].items(), key=lambda x: -x[1])[:10])
        snapshot["top_ports"]           = dict(
            sorted(stats["top_ports"].items(), key=lambda x: -x[1])[:10])
        snapshot["threat_types"]        = dict(stats["threat_types"])
        snapshot["unique_attackers"]    = list(stats["unique_attackers"])[:20]

        # Active rules summary
        snapshot["active_rules"] = get_active_rules()

        try:
            Path(STATS_FILE).parent.mkdir(parents=True, exist_ok=True)
            Path(STATS_FILE).write_text(json.dumps(snapshot, indent=2))
        except Exception as e:
            print(f"[Stats] Could not write {STATS_FILE}: {e}")

        time.sleep(CHECK_INTERVAL)

def get_active_rules():
    rules = []
    raw = run_cmd("iptables -L INPUT -v --line-numbers 2>/dev/null")
    for line in raw.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 4:
            rules.append({
                "num":    parts[0],
                "pkts":   parts[1],
                "bytes":  parts[2],
                "target": parts[3],
                "prot":   parts[4] if len(parts) > 4 else "—",
                "src":    parts[7] if len(parts) > 7 else "—",
                "dst":    parts[8] if len(parts) > 8 else "—",
                "opts":   " ".join(parts[9:]) if len(parts) > 9 else "",
            })
    return rules[:30]

# ─── CLI ────────────────────────────────────────────────────
def print_status():
    data = json.loads(Path(STATS_FILE).read_text()) if Path(STATS_FILE).exists() else {}
    print(json.dumps(data, indent=2))

def handle_signal(sig, frame):
    global running
    running = False
    print("\n[Monitor] Shutting down.")
    sys.exit(0)

# ─── Entry point ───────────────────────────────────────────
if __name__ == "__main__":
    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if len(sys.argv) > 1 and sys.argv[1] == "status":
        print_status()
        sys.exit(0)

    print("╔══════════════════════════════════════════╗")
    print("║  Firewall Monitor Daemon — Starting...   ║")
    print("╚══════════════════════════════════════════╝")
    print(f"  Stats file : {STATS_FILE}")
    print(f"  Log file   : {LOG_FILE}")
    print(f"  Auto-block : {BRUTE_THRESHOLD} hits / {BRUTE_WINDOW}s")
    print()

    t_stats = threading.Thread(target=save_stats, daemon=True)
    t_stats.start()

    tail_log()   # blocks; switches to demo_mode if log absent
