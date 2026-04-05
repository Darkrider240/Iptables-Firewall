# Enhanced IPTables Firewall — Kali Linux
**Implementation**

---

## 📁 File Overview

| File | Purpose |
|------|---------|
| `iptables_firewall.sh` | Main firewall setup script (run as root) |
| `firewall_monitor.py` | Python daemon — monitors logs & auto-blocks |
| `firewall_dashboard.html` | Browser-based GUI dashboard |

---

## 🚀 Quick Start

### Step 1 — Install the Firewall
```bash
sudo chmod +x iptables_firewall.sh
sudo ./iptables_firewall.sh install
```

### Step 2 — Start the Monitor Daemon
```bash
sudo python3 firewall_monitor.py &
```

### Step 3 — Open the Dashboard
```bash
xdg-open firewall_dashboard.html
# OR open in Firefox / Chromium
```

---

## ✅ Features Implemented

### 1. Default DENY Policy
All INPUT and FORWARD traffic is blocked by default.
Only explicitly allowed rules pass through.

```bash
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT
```

### 2. Allow Only Specific Services
Opens only SSH (22), HTTP (80), HTTPS (443).
All other ports remain closed.

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### 3. SSH Brute-Force Protection
Auto-blocks IPs after 5+ SSH attempts in 60 seconds.

```bash
iptables -A INPUT -p tcp --dport 22 -m recent --update \
  --seconds 60 --hitcount 5 --name SSH_ATTEMPTS -j DROP
```

### 4. Suspicious Activity Detection
Detects and drops:
- NULL scans (`--tcp-flags ALL NONE`)
- XMAS scans (`--tcp-flags ALL ALL`)
- FIN scans (`--tcp-flags ACK,FIN FIN`)
- SYN floods (rate-limited to 10/s)

### 5. Packet Logging
All blocked packets are tagged and logged:
- `[FW-BLOCKED]` — generic blocked packet
- `[FW-SSH-BRUTE]` — brute-force attempt
- `[FW-SYN-FLOOD]` — SYN flood
- `[FW-NULL-SCAN]` — NULL scan
- `[FW-XMAS-SCAN]` — XMAS scan
- `[FW-FIN-SCAN]` — FIN scan
- `[FW-BLOCKED-IP]` — known bad IP

Logs go to: `/var/log/firewall/firewall.log`

### 6. Trusted Traffic Only
- Loopback (`lo`) interface always allowed
- ESTABLISHED/RELATED connections allowed (stateful)
- Trusted IPs can be added to `/etc/firewall/trusted_ips.txt`

---

## 🛠 Utility Commands

```bash
# Block an IP manually
sudo ./iptables_firewall.sh block 192.168.1.200

# Unblock an IP
sudo ./iptables_firewall.sh unblock 192.168.1.200

# View current rules
sudo ./iptables_firewall.sh status

# View recent logs
sudo ./iptables_firewall.sh logs

# Flush all rules (WARNING: removes all protection)
sudo ./iptables_firewall.sh flush
```

---

## 📊 Dashboard Features

Open `firewall_dashboard.html` in any browser:

- **Live Counters** — total blocked, brute-force, scans, unique attackers
- **Activity Timeline** — 24-hour blocked packet histogram
- **Threat Matrix** — per-type event counters with flash animation
- **Port Status** — visual open/closed port overview
- **Top Attackers** — bar chart of most active source IPs
- **Live Log Table** — scrolling real-time event feed
- **Active Rules View** — current iptables rule list
- **Block/Unblock UI** — manually manage IPs from browser
- **Export Logs** — download events as CSV

---

## 📂 File Paths (on Kali Linux)

| Path | Contents |
|------|----------|
| `/var/log/firewall/firewall.log` | All firewall events |
| `/var/log/firewall/stats.json` | Dashboard stats (updated every 3s) |
| `/etc/firewall/blocked_ips.txt` | Manually + auto-blocked IPs |
| `/etc/firewall/trusted_ips.txt` | Always-allowed IPs |
| `/etc/iptables/rules.v4` | Saved iptables rules (auto-restored on boot) |

---

## ⚙️ Persistence (Auto-start on Boot)

The install script creates a systemd service:
```bash
systemctl status iptables-restore
```

To enable monitor daemon on boot, add to `/etc/rc.local`:
```bash
python3 /path/to/firewall_monitor.py &
```

---

## 🧪 Testing

```bash
# Test SSH brute-force detection (from another machine)
for i in {1..10}; do ssh invalid_user@YOUR_IP; done

# Test port scan detection
nmap -sN YOUR_IP   # NULL scan
nmap -sX YOUR_IP   # XMAS scan

# Check logs
tail -f /var/log/firewall/firewall.log
```
