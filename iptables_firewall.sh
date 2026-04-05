#!/bin/bash
# ============================================================
#   Kali Linux Enhanced Firewall - iptables Configuration
#   Features: Default Deny, Port Control, Brute-Force
#             Protection, Logging, Suspicious Activity Detection
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/firewall/firewall.log"
BLOCKED_IPS_FILE="/etc/firewall/blocked_ips.txt"
TRUSTED_IPS_FILE="/etc/firewall/trusted_ips.txt"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║      Enhanced IPTables Firewall — Kali Linux         ║"
  echo "║                   Implementation                     ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root.${NC}"
    exit 1
  fi
}

setup_dirs() {
  mkdir -p /var/log/firewall /etc/firewall
  touch "$LOG_FILE" "$BLOCKED_IPS_FILE" "$TRUSTED_IPS_FILE"
  echo -e "${GREEN}[+] Directories and log files created.${NC}"
}

log() {
  local level="$1"; shift
  echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" >> "$LOG_FILE"
  case "$level" in
    INFO)  echo -e "${GREEN}[INFO]${NC} $*" ;;
    WARN)  echo -e "${YELLOW}[WARN]${NC} $*" ;;
    ERROR) echo -e "${RED}[ERROR]${NC} $*" ;;
  esac
}

# ─────────────────────────────────────────────────────────────
# FEATURE 1: DEFAULT DENY POLICY
# Block all incoming/forwarded traffic by default.
# Only explicitly allowed traffic passes through.
# ─────────────────────────────────────────────────────────────
set_default_deny() {
  echo -e "\n${BOLD}[1/6] Setting Default DENY Policy...${NC}"

  # Flush existing rules
  iptables -F
  iptables -X
  iptables -Z
  ip6tables -F 2>/dev/null

  # Default policies
  iptables -P INPUT   DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT  ACCEPT   # Outgoing allowed; restrict if needed

  log INFO "Default DENY policy applied to INPUT and FORWARD chains."
  echo -e "${GREEN}  ✔ INPUT:   DROP (default)${NC}"
  echo -e "${GREEN}  ✔ FORWARD: DROP (default)${NC}"
  echo -e "${GREEN}  ✔ OUTPUT:  ACCEPT (default)${NC}"
}

# ─────────────────────────────────────────────────────────────
# FEATURE 2: ALLOW LOOPBACK & ESTABLISHED CONNECTIONS
# ─────────────────────────────────────────────────────────────
allow_essential() {
  echo -e "\n${BOLD}[2/6] Allowing Essential / Trusted Traffic...${NC}"

  # Loopback
  iptables -A INPUT -i lo -j ACCEPT

  # Established/related connections (stateful inspection)
  iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Load trusted IPs from file
  if [[ -s "$TRUSTED_IPS_FILE" ]]; then
    while IFS= read -r ip; do
      [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
      iptables -A INPUT -s "$ip" -j ACCEPT
      log INFO "Trusted IP allowed: $ip"
      echo -e "${GREEN}  ✔ Trusted IP: $ip${NC}"
    done < "$TRUSTED_IPS_FILE"
  fi

  log INFO "Loopback and established connections allowed."
  echo -e "${GREEN}  ✔ Loopback interface allowed${NC}"
  echo -e "${GREEN}  ✔ Stateful ESTABLISHED/RELATED allowed${NC}"
}

# ─────────────────────────────────────────────────────────────
# FEATURE 3: PORT & SERVICE CONTROL
# Only open ports 22 (SSH), 80 (HTTP), 443 (HTTPS)
# Block all other ports
# ─────────────────────────────────────────────────────────────
set_port_rules() {
  echo -e "\n${BOLD}[3/6] Configuring Port & Service Rules...${NC}"

  # Allow SSH (port 22)
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  log INFO "Port 22 (SSH) opened."
  echo -e "${GREEN}  ✔ Port 22  (SSH)   - ALLOWED${NC}"

  # Allow HTTP (port 80)
  iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
  log INFO "Port 80 (HTTP) opened."
  echo -e "${GREEN}  ✔ Port 80  (HTTP)  - ALLOWED${NC}"

  # Allow HTTPS (port 443)
  iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
  log INFO "Port 443 (HTTPS) opened."
  echo -e "${GREEN}  ✔ Port 443 (HTTPS) - ALLOWED${NC}"

  # Allow DNS responses (UDP 53)
  iptables -A INPUT -p udp --sport 53 -j ACCEPT

  # Allow ICMP ping (optional — comment out to block ping)
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit \
    --limit 1/s --limit-burst 5 -j ACCEPT

  echo -e "${YELLOW}  ✘ All other ports - BLOCKED (default deny)${NC}"
}

# ─────────────────────────────────────────────────────────────
# FEATURE 4: SSH BRUTE-FORCE PROTECTION
# Detect repeated login attempts and auto-block attacker IP
# Allows max 5 new SSH connections per 60 seconds per IP
# ─────────────────────────────────────────────────────────────
set_brute_force_protection() {
  echo -e "\n${BOLD}[4/6] Enabling SSH Brute-Force Protection...${NC}"

  # Create a dedicated chain for SSH brute-force
  iptables -N SSH_BRUTE 2>/dev/null || iptables -F SSH_BRUTE

  # Rate-limit new SSH connections per source IP
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m recent --set --name SSH_ATTEMPTS

  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 5 --name SSH_ATTEMPTS \
    -j SSH_BRUTE

  # In the brute-force chain: log then drop
  iptables -A SSH_BRUTE -m limit --limit 1/min \
    -j LOG --log-prefix "[FW-SSH-BRUTE] " --log-level 4

  iptables -A SSH_BRUTE -j DROP

  log INFO "SSH brute-force protection active: max 5 attempts per 60s per IP."
  echo -e "${GREEN}  ✔ Max 5 SSH attempts per 60 seconds per IP${NC}"
  echo -e "${GREEN}  ✔ Excess attempts → logged and dropped${NC}"
}

# ─────────────────────────────────────────────────────────────
# FEATURE 5: SUSPICIOUS ACTIVITY DETECTION & LOGGING
# Log dropped packets, port scans, NULL/XMAS scans, SYN floods
# ─────────────────────────────────────────────────────────────
set_detection_logging() {
  echo -e "\n${BOLD}[5/6] Configuring Detection & Logging Rules...${NC}"

  # ── SYN Flood Protection ──
  iptables -A INPUT -p tcp --syn \
    -m limit --limit 10/s --limit-burst 20 -j ACCEPT
  iptables -A INPUT -p tcp --syn -j LOG \
    --log-prefix "[FW-SYN-FLOOD] " --log-level 4
  iptables -A INPUT -p tcp --syn -j DROP
  echo -e "${GREEN}  ✔ SYN flood protection enabled (10/s limit)${NC}"

  # ── Port Scan / NULL Scan ──
  iptables -A INPUT -p tcp --tcp-flags ALL NONE \
    -m limit --limit 3/min \
    -j LOG --log-prefix "[FW-NULL-SCAN] " --log-level 4
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  echo -e "${GREEN}  ✔ NULL scan detection enabled${NC}"

  # ── XMAS Scan ──
  iptables -A INPUT -p tcp --tcp-flags ALL ALL \
    -m limit --limit 3/min \
    -j LOG --log-prefix "[FW-XMAS-SCAN] " --log-level 4
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  echo -e "${GREEN}  ✔ XMAS scan detection enabled${NC}"

  # ── FIN Scan ──
  iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN \
    -m limit --limit 3/min \
    -j LOG --log-prefix "[FW-FIN-SCAN] " --log-level 4
  iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
  echo -e "${GREEN}  ✔ FIN scan detection enabled${NC}"

  # ── Log all remaining dropped packets ──
  iptables -A INPUT -m limit --limit 5/min \
    -j LOG --log-prefix "[FW-BLOCKED] " --log-level 4

  log INFO "Suspicious activity detection and logging rules applied."
  echo -e "${GREEN}  ✔ All dropped packets logged with [FW-BLOCKED] prefix${NC}"

  # Rsyslog routing: direct firewall logs to dedicated file
  if [[ -d /etc/rsyslog.d ]]; then
    cat > /etc/rsyslog.d/20-firewall.conf << 'RSYSLOG'
:msg, contains, "[FW-" /var/log/firewall/firewall.log
& stop
RSYSLOG
    systemctl restart rsyslog 2>/dev/null || true
    echo -e "${GREEN}  ✔ Firewall logs routed → /var/log/firewall/firewall.log${NC}"
  fi
}

# ─────────────────────────────────────────────────────────────
# FEATURE 6: BLOCK KNOWN BAD IPs (from blocked_ips.txt)
# ─────────────────────────────────────────────────────────────
block_bad_ips() {
  echo -e "\n${BOLD}[6/6] Loading Blocked IPs...${NC}"

  iptables -N BLOCKED_IPS 2>/dev/null || iptables -F BLOCKED_IPS
  iptables -D INPUT -j BLOCKED_IPS 2>/dev/null
  iptables -I INPUT 1 -j BLOCKED_IPS

  local count=0
  if [[ -s "$BLOCKED_IPS_FILE" ]]; then
    while IFS= read -r ip; do
      [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
      iptables -A BLOCKED_IPS -s "$ip" \
        -j LOG --log-prefix "[FW-BLOCKED-IP] " --log-level 4
      iptables -A BLOCKED_IPS -s "$ip" -j DROP
      ((count++))
    done < "$BLOCKED_IPS_FILE"
  fi

  log INFO "$count IPs loaded from blocklist."
  echo -e "${GREEN}  ✔ $count IPs loaded from blocklist and blocked${NC}"
}

# ─────────────────────────────────────────────────────────────
# SAVE & PERSIST RULES
# ─────────────────────────────────────────────────────────────
save_rules() {
  echo -e "\n${BOLD}Saving Rules...${NC}"

  if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/firewall/rules.v4
    echo -e "${GREEN}  ✔ Rules saved to /etc/iptables/rules.v4${NC}"
  fi

  # Create systemd service to restore on boot
  cat > /etc/systemd/system/iptables-restore.service << 'SERVICE'
[Unit]
Description=Restore iptables firewall rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore < /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload 2>/dev/null
  systemctl enable iptables-restore 2>/dev/null || true
  log INFO "Rules saved and persistence configured."
}

show_summary() {
  echo -e "\n${CYAN}${BOLD}════ FIREWALL SUMMARY ════${NC}"
  echo ""
  iptables -L -v --line-numbers 2>/dev/null | head -60
  echo ""
  echo -e "${GREEN}${BOLD}✔ Firewall successfully configured!${NC}"
  echo -e "${CYAN}  Dashboard: open firewall_dashboard.html in a browser${NC}"
  echo -e "${CYAN}  Live logs:  tail -f $LOG_FILE${NC}"
  echo ""
}

# ─────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────
block_ip() {
  local ip="$1"
  if [[ -z "$ip" ]]; then echo "Usage: $0 block <IP>"; exit 1; fi
  iptables -I INPUT 1 -s "$ip" -j DROP
  echo "$ip" >> "$BLOCKED_IPS_FILE"
  log WARN "IP manually blocked: $ip"
  echo -e "${RED}[+] Blocked: $ip${NC}"
}

unblock_ip() {
  local ip="$1"
  if [[ -z "$ip" ]]; then echo "Usage: $0 unblock <IP>"; exit 1; fi
  iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
  sed -i "/^$ip$/d" "$BLOCKED_IPS_FILE"
  log INFO "IP unblocked: $ip"
  echo -e "${GREEN}[+] Unblocked: $ip${NC}"
}

show_logs() {
  echo -e "${CYAN}${BOLD}═══ Recent Firewall Logs ═══${NC}"
  tail -50 "$LOG_FILE" 2>/dev/null || dmesg | grep "\[FW-" | tail -50
}

status() {
  echo -e "${CYAN}${BOLD}═══ Firewall Status ═══${NC}"
  iptables -L -v --line-numbers
}

flush_all() {
  iptables -F; iptables -X; iptables -Z
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
  log WARN "All firewall rules flushed — system is OPEN."
  echo -e "${RED}[!] WARNING: All rules flushed. System is now open!${NC}"
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
case "${1:-install}" in
  install|start)
    banner
    check_root
    setup_dirs
    set_default_deny
    allow_essential
    set_port_rules
    set_brute_force_protection
    set_detection_logging
    block_bad_ips
    save_rules
    show_summary
    ;;
  block)   check_root; block_ip "$2" ;;
  unblock) check_root; unblock_ip "$2" ;;
  status)  status ;;
  logs)    show_logs ;;
  flush)   check_root; flush_all ;;
  *)
    echo "Usage: $0 {install|block <IP>|unblock <IP>|status|logs|flush}"
    exit 1
    ;;
esac
