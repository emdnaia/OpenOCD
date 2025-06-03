# OpenOCD - Operational Defense & Concealment Infrastructure

#### A.3.1. Kernel Security Settings
- Configure system security parameters in `/etc/sysctl.conf`:

```bash
# Network Security
net.inet.ip.forwarding=1          # Enable IP forwarding for gateway functionality

# Security Hardening
kern.wxabort=1                    # Abort on W^X violations (memory protection)
hw.smt=1                          # Enable Simultaneous Multithreading (performance vs security trade-off)
vm.malloc_conf=S                  # Enable malloc security features

# Security Level Configuration
sysctl kern.securelevel=1         # Moderate security level for operational flexibility
#sysctl kern.securelevel=2        # High security level (uncomment when done with experimental PF configurations)

```

- **Level 1:** Moderate restrictions, allows most administrative tasks
- **Level 2:** High security, prevents many system modifications (production)

**Apply settings:**
```bash
# Apply immediately (temporary)
sysctl net.inet.ip.forwarding=1
sysctl kern.wxabort=1

# Permanent settings are loaded from /etc/sysctl.conf at boot
# Verify current settings
sysctl kern.securelevel
sysctl net.inet.ip.forwarding
```

#### C.1. Proxmox Hypervisor Traffic Forwarding

Before configuring the OpenBSD PF firewall rules, it's important to understand how traffic reaches your OpenBSD security appliances when running in a virtualized environment like Proxmox.

**Architecture Overview:**
```
Internet → Proxmox Host → OpenBSD VM (PF Firewall) → Backend Services
```

In this setup:
- **Proxmox Host**: Acts as the hypervisor layer, receiving external traffic
- **OpenBSD VM**: Runs one of the PF configurations below (C.2, C.3, C.4, or C.5)
- **Backend Services**: Web servers, applications, or other VMs behind the OpenBSD firewall

**Proxmox Host Configuration:**
Configure traffic forwarding on the Proxmox host using iptables rules in `/etc/network/interfaces`:

```bash
## Network Configuration Variables
real_adapter_name="vmbr0"           # Your Proxmox bridge interface
openbsd_firewall_ip="10.10.10.13"   # IP of your OpenBSD PF firewall VM
backend_server_ip="10.10.10.20"     # IP of backend server (if direct forwarding)

## HTTPS Traffic Forwarding (Port 443)
#  trojan needs tcp
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $openbsd_firewall_ip:443
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $openbsd_firewall_ip:443

## HTTPS Traffic Forwarding (Port 443)
# hysteria needs udp
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $openbsd_firewall_ip:443
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $openbsd_firewall_ip:443

## HTTP Traffic Forwarding (Port 80)
# 
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 80 -j DNAT --to $openbsd_firewall_ip:80
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 80 -j DNAT --to $openbsd_firewall_ip:80

## SSH Traffic Forwarding (Port 22)
# Forward SSH traffic to OpenBSD firewall for access control
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 22 -j DNAT --to $openbsd_firewall_ip:22
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 22 -j DNAT --to $openbsd_firewall_ip:22

## WireGuard VPN Traffic Forwarding (Port 51820)
# Forward VPN traffic to OpenBSD firewall for VPN termination
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p udp --dport 51820 -j DNAT --to $openbsd_firewall_ip:51820
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p udp --dport 51820 -j DNAT --to $openbsd_firewall_ip:51820

## Alternative: Direct Backend Forwarding (bypass OpenBSD for specific services)
# Uncomment these if you want to forward certain traffic directly to backend servers
#post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 8080 -j DNAT --to $backend_server_ip:8080
#post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 8080 -j DNAT --to $backend_server_ip:8080
```

**Traffic Flow Examples:**

1. **Web Traffic with OpenBSD Filtering:**
   ```
   Client → Proxmox:443 → OpenBSD:443 → Backend:8080
   ```

2. **VPN Traffic:**
   ```
   VPN Client → Proxmox:51820 → OpenBSD:51820 → WireGuard Tunnel
   ```

3. **SSH Access Control:**
   ```
   Admin → Proxmox:22 → OpenBSD:22 (PF rules apply dynamic IP filtering)
   ```

**Important Notes:**
- The OpenBSD VM will receive traffic on its configured interface (typically `vio0`)
- PF rules in the OpenBSD VM will then process this forwarded traffic
- Choose one of the PF configurations below based on your security requirements
- Ensure the OpenBSD VM has proper routing back to the Proxmox host for return traffic


### B. System Automation
#### B.1. OpenBSD Cronjobs
-  add via `crontab -e`  
```
# System Startup Jobs
# - WireGuard VPN startup (30s delay to ensure network is ready)
# - Unbound DNS service restart (30s delay to ensure network is ready)
@reboot /bin/sleep 30 && /usr/local/bin/wg-quick up wg0
@reboot /bin/sleep 30 && /usr/sbin/rcctl restart unbound

# System Update Schedule (13:30 UTC)
# - Check for available patches
# - Apply system patches
# - Update installed packages
30 13 * * * /usr/sbin/syspatch -c 
32 13 * * * /usr/sbin/syspatch
35 13 * * * /usr/sbin/pkg_add -u
```
```
# Dynamic IP Management
# - Initial IP update on system startup (20s delay)
# - Regular IP updates at midnight and noon
@reboot /bin/sleep 20 && /usr/local/getpara.sh
0 0,12 * * * /usr/local/getpara.sh

# DNS Service Maintenance
# - Daily Unbound restart at 00:02 to clear cache
2 0 * * * /usr/sbin/rcctl restart unbound

# ASN and Mobile IP Monitoring
# - Initial checks on system startup (155s and 157s delays)
# - Regular checks every 4 minutes
@reboot /bin/sleep 155 && /bin/sh /usr/local/asn_allow.sh
@reboot /bin/sleep 157 && /bin/sh /usr/local/phone-ip-check.sh

*/4 * * * * /bin/sh /usr/local/asn_allow.sh 
*/4 * * * * /bin/sh /usr/local/phone-ip-check.sh
```

#### B.2. ASN Allow Script
- This script checks and updates ASN information for dynamic IPs
- Save as `/usr/local/asn_allow.sh`
```sh
#!/bin/sh

FQDN="example.myhoster.com"
ASN_FILE="/usr/local/asn_list.txt"
LOG_FILE="/usr/local/asn_update.log"
LOCK_FILE="/usr/local/asn_allow.lock"
TMP_ASN_FILE="/tmp/asn_list.tmp"

MAX_RETRIES=3
RETRY_DELAY=2
TIMEOUT=10
REQUIRED_TOOLS="dig curl jq grep sort"

log() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

retry_command() {
  local retries=0
  while [ $retries -lt $MAX_RETRIES ]; do
    "$@" && return 0
    retries=$((retries + 1))
    sleep $((RETRY_DELAY ** retries))
  done
  return 1
}

# Check dependencies
for tool in $REQUIRED_TOOLS; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    case "$tool" in
      dig) INSTALL_CMD="pkg_add bind-tools" ;;
      curl) INSTALL_CMD="pkg_add curl" ;;
      jq) INSTALL_CMD="pkg_add jq" ;;
      *) INSTALL_CMD="pkg_add $tool" ;;
    esac
    log "ERROR: Required tool '$tool' is not installed. Please install it using: $INSTALL_CMD. Exiting."
    exit 1
  fi
done

# Lock handling
if [ -f "$LOCK_FILE" ]; then
  LOCK_AGE=$(($(date +%s) - $(stat -f %m "$LOCK_FILE")))
  if [ "$LOCK_AGE" -gt 300 ]; then
    log "Stale lock file detected (age: $LOCK_AGE seconds). Removing."
    rm -f "$LOCK_FILE"
  else
    log "Another instance is running (lock file age: $LOCK_AGE seconds). Exiting."
    exit 1
  fi
fi
trap 'rm -f "$LOCK_FILE"' EXIT
touch "$LOCK_FILE"
chmod 600 "$LOCK_FILE"

if [ ! -f "$ASN_FILE" ]; then
  touch "$ASN_FILE"
  chmod 600 "$ASN_FILE"
fi
log "=== Starting asn_allow.sh with RIPEstat API for $FQDN ==="

IP="$(retry_command dig +short "$FQDN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
if [ -z "$IP" ]; then
  log "ERROR: Failed to resolve FQDN: $FQDN"
  exit 1
fi
log "Resolved $FQDN → $IP"

if [ -s "$ASN_FILE" ]; then
  if grep -qF "$IP" "$ASN_FILE"; then
    log "IP $IP is already covered. Skipping update."
    exit 0
  fi
fi
log "IP $IP is not covered. Proceeding with ASN retrieval."

RAW_RESPONSE=$(retry_command curl -m $TIMEOUT -s "https://ipinfo.io/$IP")
ASN=$(echo "$RAW_RESPONSE" | grep '"org":' | sed -E 's/.*"org": *"([^"]*)".*/\1/' | grep -Eo '^AS[0-9]+')
if [ -z "$ASN" ]; then
  log "ERROR: Could not parse ASN from ipinfo.io for $IP. Raw response: $RAW_RESPONSE"
  exit 1
fi
log "Identified ASN: $ASN for $IP"

retry_command curl -m $TIMEOUT -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$ASN" | \
  jq -r '.data.prefixes[].prefix' | sort -u > "$TMP_ASN_FILE"

COUNT_ALL=$(wc -l < "$TMP_ASN_FILE")
if [ "$COUNT_ALL" -eq 0 ]; then
  log "ERROR: No routes found for ASN: $ASN"
  rm -f "$TMP_ASN_FILE"
  exit 1
fi
log "Found $COUNT_ALL routes for ASN: $ASN"

if cmp -s "$TMP_ASN_FILE" "$ASN_FILE"; then
  log "ASN file is up-to-date. No changes needed."
else
  mv "$TMP_ASN_FILE" "$ASN_FILE"
  log "ASN routes updated and saved to $ASN_FILE"
fi

rm -f "$TMP_ASN_FILE"
log "=== asn_allow.sh done ==="
```

#### B.3. Phone IP Check Script
- This script monitors IP changes for mobile devices
- Save as `/usr/local/phone-ip-check.sh`
  
```sh
#!/bin/sh

# FQDNs to compare
FQDN1="example1.hoster1.com"
FQDN2="example2.hoster2.com"

# Function to resolve IP and return only the first valid IP
get_ip() {
    dig +short "$1" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1
}

# Get IPs for both FQDNs
IP1=$(get_ip "$FQDN1")
IP2=$(get_ip "$FQDN2")

# Check if we got valid IPs
if [ -z "$IP1" ] || [ -z "$IP2" ]; then
    logger "phone-ip-check: Failed to resolve one or both FQDNs"
    exit 1
fi

# Check if IPs are different
if [ "$IP1" != "$IP2" ]; then
    # Run the getpara script if IPs are different
    /usr/local/getpara.sh
    logger "phone-ip-check: Different IPs detected ($IP1 vs $IP2), ran getpara.sh"
else
    logger "phone-ip-check: IPs are the same or FQDN2 not set, no action needed"
fi

# Debug via pf
# pfctl -t dynamic_hosts -T show
#
# via fw log
# tail -f /usr/local/firewall_update.log
#
# via openbsd
# tail -f /var/log/messages | grep "phone-ip-check"
### B.4. System Debugging and Troubleshooting
```

- You edit the pf rules on ` /etc/pf.conf ` and check via  `pfctl -nf /etc/pf.conf` and  load them via  `pfctl -f  /etc/pf.conf` | non - webserver example
  
#### C2A

```
# $OpenBSD: pf.conf,v 1.55 2017/12/03 20:40:04 sthen Exp $
#
# See pf.conf(5) and /etc/examples/pf.conf

#-----  examples start #----- 
#ban evil like:
#table <abusive_ips> persist
#block quick from <abusive_ips>

###  could be doing redirection like:
#pass in log on vio0 proto {tcp,udp} from <dynamic_hosts> to (vio0) port 443 rdr-to 127.0.0.1 port 8080 keep state

# Configuration Variables
dynamic_hosts_file="/usr/local/gotten-para"  # Location for dynamic hosts
wireguard_port="51820"                        # Your WireGuard VPN port
wireguard_net="10.0.0.0/24"                 # Your WireGuard VPN network
ssh_allowed_ips="{6.6.6.6/32, 7.7.7.7/32}"  # IPs allowed for SSH
wireguard_iface="wg0"                       # WireGuard interface identifier

# ===== Basic Security Settings =====
# Block all IPv6 traffic for security
block drop quick inet6

# we go block-drop
set block-policy drop
set skip on lo  # Skip loopback traffic

# Anti-spoofing rule for external interface
antispoof quick for vio0 inet

# ---- Scrubbing ----
# Basic packet scrubbing
match in on vio0 scrub (no-df random-id max-mss 1440 reassemble tcp)

#block drop quick from <abusive_ips>
block return in log on !lo0 proto tcp to port 6000:6010

# Prevent network access for _pbuild user
block drop out log proto {tcp udp} user _pbuild

# ---- DHCP/BOOTP Blocking ----
# Block broadcast DHCP traffic
block drop in log quick on vio0 proto udp from any to 255.255.255.255 port 67:68

# Block all DHCP/BOOTP traffic
block drop in log quick on vio0 proto udp from any to any port 67:68

# ---- Block Private Addresses ----
# Block spoofed private addresses on external interface
block drop in log quick on vio0 from {10.0.0.0/8 , 172.16.0.0/12, 192.168.0.0/16, 255.255.255.255/32} to any

# ---- SSH Rule ----
# Allow SSH from specific IPs
pass in quick on vio0 proto tcp from {<dynamic_hosts>, $ssh_allowed_ips} to (vio0) port 22 keep state

# Block all inbound traffic by default
block drop in log on vio0 all

# NAT for outgoing traffic
match out on egress inet from $wireguard_net to any nat-to (egress:0)
#match out on egress inet from !(egress:network) to any nat-to (egress:0)

# allow trojan-gfw / hystria2
pass in log on vio0 proto { tcp, udp } from <dynamic_hosts> to (vio0) port {443} keep state
# allow DOT 
pass in log on vio0 proto { tcp, udp } from <dynamic_hosts> to (vio0) port {853} keep state

# ---- WireGuard Rules ----
# Allow WireGuard traffic from dynamic hosts
pass in quick on vio0 proto udp from <dynamic_hosts> to (vio0) port $wireguard_port keep state
pass out quick on vio0 proto udp to <dynamic_hosts> port $wireguard_port keep state

# Allow all traffic on WireGuard interface
pass in on $wireguard_iface from $wireguard_net to any keep state
pass out on $wireguard_iface from any to $wireguard_net keep state

# ---- Outbound Traffic ----
# Allow all outbound traffic
#pass out on vio0 all flags S/SA keep state
pass out on vio0 keep state
```

#### C2B 

```
# $OpenBSD: pf.conf,v 1.55 2017/12/03

wireguard_port="{51820}"
wireguard_net="10.0.0.0/24"

ssh_allowed_ips="{1.1.1.1/32, 8.8.8.8/32, 10.0.1.1/32, 10.0.1.34/32}"

table <dynamic_hosts> persist file "/usr/local/gotten-para"
table <asn>            persist file "/usr/local/asn_list.txt"

block drop quick inet6

set block-policy drop

set skip on lo

block drop in on vio0 proto tcp flags U/U

antispoof quick for vio0 inet

match in on vio0 scrub (no-df random-id max-mss 1440 reassemble tcp)

block return in  on !lo0 proto tcp to port 6000:6010
block return out log proto { tcp udp } user _pbuild

block drop  in  log on vio0 from { 10.0.0.0/8 , 172.16.0.0/12 , 192.168.0.0/16 , 255.255.255.255/32 } to any

pass  in   quick on vio0 proto tcp from $ssh_allowed_ips to (vio0) port 22 keep state

block drop in  log on vio0 all

match out  on egress inet from $wireguard_net to any nat-to (egress:0)

#pass in log on vio0 proto {tcp,udp} from <dynamic_hosts> to (vio0) port { 80,443 } keep state
#pass in log on vio0 proto tcp from $wireguard_net to 10.1.6.27 port 443 rdr-to 10.2.6.207 port 443 keep state

pass  in   log on vio0 proto udp from <asn>            to (vio0) port $wireguard_port keep state
pass  in   log on vio0 proto udp from <dynamic_hosts>  to (vio0) port $wireguard_port keep state
pass  in   log on vio0 proto udp from 10.0.0.25        to (vio0) port $wireguard_port keep state

pass  in   on  wg0 from $wireguard_net to any keep state
pass  out  on  wg0 from any to $wireguard_net keep state
pass  out  on  vio0 keep state

```

### D. Dynamic IP Management
#### D.1. Dynamic Hosts Script
- Important: All your clients will need to get FQDNs, and you can do that by adding for example containers in your home, work etc, that use any DYNDNS-hoster.
- Next, *Ensure you replace `hoster1 + hoster2` with your actual domains to allow dynamic access from.*
- The script below will access the FQDN and add it to the firewall ruletable for access.

I've deployed the following script on `/usr/local/getpara.sh` it creates `temp_gotten_para` as well as `gotten-para` which contains the dynamic IPs to be added to the firewall for access.

```sh
#!/bin/sh

# Dynamic PF Table Updater
# Version 4.1 - OpenBSD Optimized

# Configuration
FQDNS="example1.myhoster.com example2.yourhoster.com"
WORK_DIR="/usr/local"
FINAL_IP_FILE="$WORK_DIR/gotten-para"
LOG_FILE="$WORK_DIR/firewall_update.log"
LOCK_FILE="$WORK_DIR/getpara.lock"
MAX_IP_COUNT=3
RETENTION_DAYS=7
RETRY_DELAY=2
MAX_RETRIES=3
RIPE_API_URL="https://stat.ripe.net/data/resolvedns/data.json"

# DNS Infrastructure
DNS_TIMEOUT=2                      # Seconds per DNS query
RESOLVER_DELAY=1                   # Seconds between resolver attempts
SYSTEM_RESOLVERS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
FALLBACK_DNS="8.8.8.8 1.1.1.1 9.9.9.9"
DNS_CHECK_DOMAINS="example.com example.net example.org"

# Security Hardening
umask 077
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin"
CURL_OPTIONS="--silent --max-time 10 --retry 2 --proto-default https"

# Atomic Logging System
log() {
    entry="$(date "+%Y-%m-%d %H:%M:%S") - $1"
    echo "$entry" >> "$LOG_FILE"
    chmod 600 "$LOG_FILE"          # Maintain strict permissions
    logger -t "pf-updater" "$1"    # Syslog integration
}

# Validation Routines
validate_ip() {
    echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

validate_fqdn() {
    echo "$1" | grep -Eq '^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$'
}

# Resolver Infrastructure
resolver_health_check() {
    for resolver in $SYSTEM_RESOLVERS $FALLBACK_DNS; do
        log "Testing resolver: $resolver"
        if dig +time=$DNS_TIMEOUT +tries=1 +retry=0 @"$resolver" $DNS_CHECK_DOMAINS >/dev/null 2>&1; then
            log "Resolver operational: $resolver"
            return 0
        fi
        sleep $RESOLVER_DELAY
    done
    log "CRITICAL: All DNS resolvers offline"
    return 1
}

resolver_sequence() {
    fqdn=$1
    for resolver in $SYSTEM_RESOLVERS $FALLBACK_DNS; do
        log "Attempting resolution via $resolver"
        ip=$(dig +time=$DNS_TIMEOUT +short @"$resolver" "$fqdn" 2>/dev/null | \
            grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -1)
        
        [ -n "$ip" ] && validate_ip "$ip" && { echo "$ip"; return 0; }
        sleep $RESOLVER_DELAY
    done
    return 1
}

# Package Assurance
verify_dependencies() {
    for pkg in pfctl awk curl jq dig; do
        if ! command -v $pkg >/dev/null; then
            log "Dependency missing: $pkg"
            pkg_add -I "$pkg" || { log "Failed to install $pkg"; exit 3; }
        fi
    done
}

# Concurrency Control
establish_lock() {
    if [ -f "$LOCK_FILE" ]; then
        LOCK_AGE=$(($(date +%s) - $(stat -f %m "$LOCK_FILE")))
        [ $LOCK_AGE -gt 300 ] && rm -f "$LOCK_FILE" || { log "Active lock detected"; exit 1; }
    fi
    trap 'rm -f "$LOCK_FILE"' EXIT
    > "$LOCK_FILE"
}

# Resolution Workflow
resolve_with_fallback() {
    fqdn=$1
    validate_fqdn "$fqdn" || { log "Invalid FQDN: $fqdn"; return 1; }

    # Phase 1: RIPE API
    log "Initiating RIPE API query for $fqdn"
    response=$(curl $CURL_OPTIONS "$RIPE_API_URL?resource=$fqdn&type=A")
    ripe_ip=$(echo "$response" | jq -r '.data.records[0][0].value' 2>/dev/null)
    
    if validate_ip "$ripe_ip"; then
        log "RIPE resolution successful: $ripe_ip"
        echo "$ripe_ip"
        return 0
    fi

    # Phase 2: DNS Resolver Sequence
    log "Falling back to DNS resolution"
    resolver_sequence "$fqdn"
}

# PF Table Management
update_pf_table() {
    log "Compiling PF table entries"
    echo -e "$resolved_ips" | awk -v max=$MAX_IP_COUNT '
        !seen[$1]++ { print $1 }
        NR >= max { exit }
    ' > "$FINAL_IP_FILE"

    [ -s "$FINAL_IP_FILE" ] && {
        log "Executing atomic PF table update"
        pfctl -t dynamic_hosts -T replace -f "$FINAL_IP_FILE" || {
            log "PF update failed - preserving previous state";
            return 1;
        }
    }
}

# Main Execution Flow
establish_lock
log "=== INITIALIZING FIREWALL UPDATE ==="
log "Resolver hierarchy: System: [$SYSTEM_RESOLVERS] → Fallbacks: [$FALLBACK_DNS]"

verify_dependencies
resolver_health_check || { log "DNS infrastructure failure"; exit 2; }

# Resolution Pipeline
resolved_ips=""
for fqdn in $FQDNS; do
    ip=$(resolve_with_fallback "$fqdn") && {
        resolved_ips="$resolved_ips\n$ip"
        log "Resolution confirmed: $fqdn → $ip"
    } || log "Resolution failed: $fqdn"
done

update_pf_table
log "=== FIREWALL UPDATE COMPLETED ==="
```

### E. VPN Configuration
#### E.1. WireGuard Setup - Kernel Mode (OpenBSD 7.6+)
- Guide: https://docs.vultr.com/install-wireguard-vpn-server-on-openbsd-7-0
- **Important:** OpenBSD now includes WireGuard in the kernel, providing better performance and integration

**Installation:**
```bash
# Install WireGuard tools
pkg_add wireguard-tools

# Generate server keys
sh -c 'umask 077; wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key'

# Generate client keys (repeat for each client)
sh -c 'umask 077; wg genkey | tee client-private.key | wg pubkey > client-public.key'
```

#### E.2. Server Configuration

**Step 1: Create WireGuard configuration file**
- Save as `/etc/wireguard/wg0.conf`:
```
[Interface]
# Note: Address removed for kernel mode - configured in hostname.wg0
ListenPort = 51820
PrivateKey = YOUR_SERVER_PRIVATE_KEY_HERE

[Peer]
# Client 1
PublicKey = CLIENT1_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.2/32

[Peer]
# Client 2  
PublicKey = CLIENT2_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.3/32

[Peer]
# Client 3
PublicKey = CLIENT3_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.4/32
```

**Step 2: Create kernel mode interface configuration**
- Create `/etc/hostname.wg0`:
```
inet 10.0.0.1 255.255.255.0 NONE
#mtu 1420
!/usr/local/bin/wg setconf wg0 /etc/wireguard/wg0.conf
up
```


#### E.3. Client Configuration

**Desktop/Mobile Client Example:**
```
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_HERE
Address = 10.0.0.2/24
DNS = 10.0.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.0/24
Endpoint = YOUR_SERVER_PUBLIC_IP:51820
PersistentKeepalive = 25
```

**Full Tunnel Client (Route all traffic through VPN):**
```
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_HERE
Address = 10.0.0.2/24
DNS = 10.0.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY_HERE
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = YOUR_SERVER_PUBLIC_IP:51820
PersistentKeepalive = 25
```

### F. DNS Configuration
#### F.0: (builtin) unbound 

- configure on `/var/unbound/etc/unbound.conf`

```
# $OpenBSD: unbound.conf,v 1.21 2020/10/28 11:35:58 sthen Exp $

server:
  # Logging
  # logfile: "/var/log/unbound.log"
  # verbosity: 2
  # log-queries: yes

  # Listen interfaces
  interface: 127.0.0.1@53
  interface: 10.0.0.1@53
  interface: 127.0.0.1@853
  interface: 10.0.0.1@853
  # interface: 0.0.0.0@53
  # interface: ::1
  do-ip4: yes
  do-ip6: no
  do-udp: yes
  do-tcp: yes
 
 # Access control
  access-control: 127.0.0.1 allow
  access-control: 10.0.0.0/24 allow
  access-control: ::0/0 refuse


  # Security settings
  hide-identity: yes
  hide-version: yes

  # Use DNSSEC
  auto-trust-anchor-file: "/var/unbound/db/root.key"
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-short-bufsize: yes
  aggressive-nsec: yes

  # TLS configuration
  tls-cert-bundle: "/etc/ssl/cert.pem"
  tls-port: 853
  tls-service-key: "/var/unbound/etc/unbound_server.key"
  tls-service-pem: "/var/unbound/etc/unbound_server.pem"

  # Performance tuning
#  num-threads: 3
#  so-reuseport: no
#  num-queries-per-thread: 2048
#  outgoing-range: 4096
#  msg-cache-size: 256m
#  rrset-cache-size: 256m
#  msg-cache-slabs: 4
#  rrset-cache-slabs: 4
#  infra-cache-slabs: 4
#  key-cache-slabs: 4
  cache-min-ttl: 300
  cache-max-ttl: 86400
  prefetch: yes
  prefetch-key: yes
#  val-permissive-mode: yes
  serve-expired: yes
  serve-expired-ttl: 86400
#  so-rcvbuf: 0
#  so-sndbuf: 0
#  edns-buffer-size: 1472
#  stream-wait-size: 16m
  qname-minimisation: yes
#  rrset-roundrobin: yes
  fast-server-permil: 700
  fast-server-num: 4

forward-zone:
  name: "."
  forward-first: yes
  forward-tls-upstream: yes
 # you could forward to the gree-podman-version-below-like-that
 # forward-addr: 10.0.0.55
  forward-addr: 9.9.9.9@853#dns.quad9.net
  forward-addr: 1.1.1.1@853#cloudflare-dns.com
  forward-addr: 8.8.8.8@853#dns.google

```

#### F.1: greed DNS on another Linux box
- use adguard via docker or podman
``` 
#!/bin/bash

# =========================================================================
# ADGUARD HOME DEPLOYMENT SCRIPT V3 - COMPREHENSIVE PRODUCTION SETUP
# =========================================================================
# Purpose: Deploy AdGuard Home with DoT/DoH/DoQ, performance optimization
# Features: Self-signed certs, SELinux-aware, resource constraints
# Last Modified: 2025-01-XX
# =========================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADGUARD_DIR="${SCRIPT_DIR}/adguard-home"
CONTAINER_NAME="adguard-home"
IMAGE_NAME="adguard/adguardhome:latest"

# Network Configuration (sanitized)
ADGUARD_IP="10.0.0.33"
NETWORK_SUBNET="10.0.0.0/24"
DNS_UPSTREAM_1="1.1.1.1"
DNS_UPSTREAM_2="cloudflare.com"

# Resource Constraints
MEMORY_LIMIT="12g"
CPU_LIMIT="3"
SWAP_LIMIT="2g"

# Logging
LOG_FILE="${SCRIPT_DIR}/adguard-deployment.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=== AdGuard Home Deployment Started ==="

# Create directory structure
log "Creating directory structure..."
mkdir -p "${ADGUARD_DIR}"/{conf,work,ssl,logs}
chmod 755 "${ADGUARD_DIR}"
chmod 755 "${ADGUARD_DIR}"/{conf,work,ssl,logs}

# Generate self-signed certificates for DoT/DoH/DoQ
log "Generating self-signed certificates..."
openssl req -x509 -newkey rsa:4096 -keyout "${ADGUARD_DIR}/ssl/server.key" \
    -out "${ADGUARD_DIR}/ssl/server.crt" -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=${ADGUARD_IP}" \
    -addext "subjectAltName=IP:${ADGUARD_IP},IP:127.0.0.1,DNS:localhost"

# Set proper permissions for certificates
chmod 644 "${ADGUARD_DIR}/ssl/server.crt"
chmod 600 "${ADGUARD_DIR}/ssl/server.key"

# Create comprehensive AdGuardHome.yaml configuration
log "Creating AdGuardHome.yaml configuration..."
cat > "${ADGUARD_DIR}/conf/AdGuardHome.yaml" << 'EOF'
# AdGuard Home Configuration - Production Optimized
# Generated: 2025-01-XX

http:
  address: 0.0.0.0:3000
  session_ttl: 720h

users:
  - name: admin
    password: $2a$10$example.hash.replace.with.your.own.bcrypt.hash

auth_attempts: 5
block_auth_min: 15

theme: auto
debug_pprof: false
web_session_ttl: 720

dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  
  # Statistics and query logging
  statistics_interval: 24h
  querylog_enabled: true
  querylog_file_enabled: true
  querylog_interval: 2160h
  querylog_size_memory: 1000
  
  # Anonymization
  anonymize_client_ip: true
  
  # Performance settings
  protection_enabled: true
  blocking_mode: default
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 10
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  
  # Rewrites and custom rules
  rewrites: []
  blocked_services: []
  upstream_timeout: 10s
  
  # Bootstrap DNS
  bootstrap_dns:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 2606:4700:4700::1111
    - 2001:4860:4860::8888
  
  # Upstream DNS servers with DoT/DoH
  upstream_dns:
    - tls://1.1.1.1
    - tls://1.0.0.1
    - https://cloudflare-dns.com/dns-query
    - tls://8.8.8.8
    - tls://8.8.4.4
    - https://dns.google/dns-query
    - tls://9.9.9.9
    - https://dns.quad9.net/dns-query
  
  # Upstream mode
  upstream_mode: load_balance
  fastest_timeout: 1s
  
  # Cache settings
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 86400
  cache_optimistic: true
  
  # DNSSEC
  enable_dnssec: true
  
  # EDNS Client Subnet
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  
  # Rate limiting
  ratelimit: 20
  ratelimit_whitelist: []
  
  # Refuse ANY requests
  refuse_any: true
  
  # IPv6 settings
  resolve_clients: true
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
  
  # Filtering settings
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: true
  
  # Custom filtering rules
  user_rules:
    - "||example-ads.com^"
    - "||tracking.example.com^"
    - "@@||allowlist.example.com^"

# TLS Configuration for DoT/DoH/DoQ
tls:
  enabled: true
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  certificate_chain: "/opt/adguardhome/ssl/server.crt"
  private_key: "/opt/adguardhome/ssl/server.key"
  certificate_path: ""
  private_key_path: ""
  strict_sni_check: false

# Filters - Production-ready filter lists
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  
  - enabled: true
    url: https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers_justdomains.txt
    name: AdGuard CNAME-cloaked trackers
    id: 2


# Whitelist filters
whitelist_filters: []

# DHCP settings (disabled by default)
dhcp:
  enabled: false
  interface_name: ""
  local_domain_name: lan
  dhcpv4:
    gateway_ip: ""
    subnet_mask: ""
    range_start: ""
    range_end: ""
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: ""
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false

# Client settings
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []

# Log settings
log_file: ""
log_max_backups: 0
log_max_size: 100
log_max_age: 3
log_compress: false
log_localtime: false
verbose: false

# OS settings
os:
  group: ""
  user: ""
  rlimit_nofile: 0

# Schema version
schema_version: 20
EOF

# Stop and remove existing container if it exists
log "Stopping and removing existing container..."
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    podman stop "${CONTAINER_NAME}" || true
    podman rm "${CONTAINER_NAME}" || true
fi

# Pull latest AdGuard Home image
log "Pulling latest AdGuard Home image..."
podman pull "${IMAGE_NAME}"

# SELinux context setup (if SELinux is enabled)
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    log "Setting SELinux contexts..."
    sudo setsebool -P container_manage_cgroup true
    sudo semanage fcontext -a -t container_file_t "${ADGUARD_DIR}(/.*)?" 2>/dev/null || true
    sudo restorecon -R "${ADGUARD_DIR}"
fi

# Create and start AdGuard Home container
log "Creating AdGuard Home container..."
podman run -d \
    --name "${CONTAINER_NAME}" \
    --restart=unless-stopped \
    --memory="${MEMORY_LIMIT}" \
    --cpus="${CPU_LIMIT}" \
    --memory-swap="${SWAP_LIMIT}" \
    --security-opt label=disable \
    --cap-drop=ALL \
    --cap-add=NET_BIND_SERVICE \
    --cap-add=CHOWN \
    --cap-add=SETUID \
    --cap-add=SETGID \
    -p 53:53/tcp \
    -p 53:53/udp \
    -p 3000:3000/tcp \
    -p 443:443/tcp \
    -p 443:443/udp \
    -p 853:853/tcp \
    -p 853:853/udp \
    -v "${ADGUARD_DIR}/work:/opt/adguardhome/work:Z" \
    -v "${ADGUARD_DIR}/conf:/opt/adguardhome/conf:Z" \
    -v "${ADGUARD_DIR}/ssl:/opt/adguardhome/ssl:Z" \
    "${IMAGE_NAME}"

# Wait for container to start
log "Waiting for AdGuard Home to start..."
sleep 10

# Verify container is running
if podman ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    log "✓ AdGuard Home container started successfully"
    
    # Display connection information
    log "=== AdGuard Home Access Information ==="
    log "Web Interface: http://localhost:3000"
    log "DNS Server: ${ADGUARD_IP}:53"
    log "DNS over TLS: ${ADGUARD_IP}:853"
    log "DNS over HTTPS: https://${ADGUARD_IP}/dns-query"
    log "DNS over QUIC: quic://${ADGUARD_IP}:853"
    log ""
    log "Default credentials:"
    log "Username: admin"
    log "Password: [Set during initial setup]"
    log ""
    log "Certificate files:"
    log "Certificate: ${ADGUARD_DIR}/ssl/server.crt"
    log "Private Key: ${ADGUARD_DIR}/ssl/server.key"
    
    # Show container status
    log "=== Container Status ==="
    podman ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    
    # Show resource usage
    log "=== Resource Usage ==="
    podman stats --no-stream "${CONTAINER_NAME}" --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
    
else
    log "✗ Failed to start AdGuard Home container"
    log "Container logs:"
    podman logs "${CONTAINER_NAME}"
    exit 1
fi

# Create systemd service for auto-start (optional)
log "Creating systemd service..."
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/adguard-home.service << EOF
[Unit]
Description=AdGuard Home Container
Wants=network-online.target
After=network-online.target
RequiresMountsFor=%t/containers

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
TimeoutStopSec=70
ExecStart=/usr/bin/podman start ${CONTAINER_NAME}
ExecStop=/usr/bin/podman stop -t 10 ${CONTAINER_NAME}
Type=forking
PIDFile=%t/%n.pid

[Install]
WantedBy=default.target
EOF

# Enable systemd service
systemctl --user daemon-reload
systemctl --user enable adguard-home.service

log "=== Deployment Complete ==="
log "AdGuard Home has been successfully deployed!"
log "Configuration file: ${ADGUARD_DIR}/conf/AdGuardHome.yaml"
log "Log file: ${LOG_FILE}"
log ""
log "Next steps:"
log "1. Access web interface at http://localhost:3000"
log "2. Complete initial setup wizard"
log "3. Configure your devices to use ${ADGUARD_IP} as DNS server"
log "4. Test encrypted DNS: dig @${ADGUARD_IP} -p 853 +tls-ca=${ADGUARD_DIR}/ssl/server.crt example.com"
log ""
log "To manage the container:"
log "  Start:   podman start ${CONTAINER_NAME}"
log "  Stop:    podman stop ${CONTAINER_NAME}"
log "  Logs:    podman logs ${CONTAINER_NAME}"
log "  Status:  podman ps -a --filter name=${CONTAINER_NAME}"
```

### Squid

- remember to first time initialize
```
pkg_add -u
pkg_add squid
rcctl enable squid
rcctl restart squid
squid -z #this is requred or it will not work
```

#### Squid Configuration
- Save as `/etc/squid/squid.conf`
```
#################################################################
# ULTIMATE PARANOID SQUID CONFIG – OpenBSD 7.6 / Squid 6.10 (v1.1)
# posture-aware header sets · full XFF removal · 2025-05-22
#################################################################

#########################
# CORE NETWORK SETTINGS #
#########################
http_port                10.0.0.1:3128
tcp_outgoing_address     10.0.0.1
visible_hostname         your-server.local
via                      off
forwarded_for            delete    
follow_x_forwarded_for   deny all
httpd_suppress_version_string on
#connection_auth          allow none

# DNS (Unbound ➜ WireGuard peer)
dns_nameservers          127.0.0.1 10.0.0.1
dns_v4_first             on
dns_defnames             off

##################
# CACHE DISABLED #
##################
cache_mem                0 MB
memory_cache_mode        disk
cache deny               all
cache_dir ufs /var/squid/cache 100 16 256
coredump_dir /var/squid/cache

##########################
#   ACLS – SOURCE        #
##########################
acl localnet     src 10.0.0.0/24
acl localhost    src 127.0.0.1/32

##########################
#   ACLS – DESTINATION   #
##########################
acl local_dests  dst 10.0.0.0/24
always_direct    allow local_dests

##########################
#   ACLS – PORTS/METHODS #
##########################
acl SSL_ports     port 443
acl Safe_ports    port 80 443
acl Safe_methods  method GET HEAD POST OPTIONS CONNECT

#######################
#  POSTURE SELECTORS  #
#######################
acl mode_defensive  note posture:def
acl mode_offensive  note posture:off

##########################
#    MAIN ACCESS RULES   #
##########################
http_access deny  !Safe_ports
http_access deny  CONNECT !SSL_ports
http_access deny  !Safe_methods

http_access allow localhost
http_access allow localnet
http_access deny  all

#################################################################
#                       PRIVACY  — REQUEST                      #
#################################################################

# 0) wipe or set generic User-Agent
request_header_replace   User-Agent ""        all
request_header_replace   User-Agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" mode_offensive

# 0.1) Normalise languages
request_header_replace   Accept-Language "en-US,en;q=0.9"

# 1) tracking headers
request_header_access    From                      deny all
request_header_access    Referer                   deny all
request_header_access    Cookie                    deny all
request_header_access    DNT                       deny all
request_header_access    X-Forwarded-For           deny all
request_header_access    Proxy-Connection          deny all
request_header_access    Upgrade-Insecure-Requests deny all
request_header_access    If-None-Match             deny all   
request_header_access    Cache-Control             deny all
request_header_access    Pragma                    deny all
request_header_access    Purpose                   deny all
request_header_access    Early-Data                deny all
request_header_access    Priority                  deny all
request_header_access    Alt-Used                  deny all

# 2) Client-hint headers
acl ch_hint req_header -i ^Sec-CH-
request_header_access    ch_hint                   deny all
request_header_access    Accept-CH                 deny all
request_header_access    Critical-CH               deny all
request_header_access    Save-Data                 deny all

# 3) Sec-Fetch*   (unified top-navigation look)
request_header_replace   Sec-Fetch-Site  "cross-site"    mode_offensive
request_header_replace   Sec-Fetch-Mode  "navigate"
request_header_replace   Sec-Fetch-Dest  "document"
request_header_replace   Sec-Fetch-User  "?1"

# 4) Normalise core Accept*
request_header_replace   Accept-Encoding "gzip, deflate, br"
request_header_replace   Accept          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" mode_offensive
request_header_access    Accept-Charset  deny all    # keep absent

# -- optional extra hardening (disabled by default) --
# Strip Accept-Encoding entirely in defensive posture to block zstd & brotli
# request_header_access  Accept-Encoding deny mode_defensive

# allow anything else
request_header_access    All allow all

#################################################################
#                       PRIVACY  — RESPONSE                     #
#################################################################
reply_header_access Server          deny all
reply_header_access X-Powered-By    deny all
reply_header_access X-Cache         deny all
reply_header_access X-Cache-Lookup  deny all
reply_header_access Via             deny all
reply_header_access Set-Cookie      deny all
reply_header_access Set-Cookie2     deny all
reply_header_access ETag            deny all
reply_header_access Last-Modified   deny all
reply_header_access Alt-Svc         deny all     # blocks HTTP/3 hints
reply_header_access Public-Key-Pins deny all
reply_header_access Report-To       deny all
reply_header_access Server-Timing   deny all
reply_header_access X-Unique-ID     deny all
reply_header_access All             allow all

# Security extras
reply_header_add X-Frame-Options           "DENY"
reply_header_add X-Content-Type-Options    "nosniff"
reply_header_add Referrer-Policy           "no-referrer"
reply_header_add Strict-Transport-Security "max-age=31536000; includeSubDomains"
reply_header_add Permissions-Policy        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), usb=(), interest-cohort=()"

#############################
#         TIMEOUTS          #
#############################
forward_timeout              30 seconds
connect_timeout              30 seconds
read_timeout                 30 seconds
request_timeout              30 seconds
persistent_request_timeout    1 minute
client_lifetime              15 minutes
pconn_timeout                1 minute
shutdown_lifetime            1 second
half_closed_clients          off

########################
# DISABLED PROTOCOLS   #
########################
icp_port 0
htcp_port 0
snmp_port 0
ident_lookup_access deny all
icp_access   deny all
htcp_access  deny all
snmp_access  deny all

####################
# LOGGING DISABLED #
####################
access_log none
cache_log   stdio:/dev/null
pid_filename /var/squid/run/squid.pid


#################################################################
# === HARDENING SUGGESTIONS
#################################################################
# (uncomment to activate)
#
# request_header_replace   Sec-CH-UA          "\"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"99\""
# request_header_replace   Sec-CH-UA-Mobile   "?0"
# request_header_replace   Sec-CH-UA-Platform "\"Windows\""
# request_header_access    ^Sec-CH-UA         allow all
#
request_header_replace   Accept-Encoding "gzip, deflate, br" mode_offensive
request_header_access    Accept-Encoding deny mode_defensive

request_header_replace   Accept "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
request_header_replace   Sec-Fetch-Site "same-site"
#################################################################

#################################################################
# === REMOVE THE FOLLOWING LINES TO ELIMINATE UNIQUE MARKERS ===
##################################################################
#request_header_replace   User-Agent ""        all
#request_header_replace   Sec-Fetch-Site  "cross-site"    mode_offensive
#request_header_replace   Accept-Encoding "gzip, deflate, br"
##################################################################
```

### J. Browser Configuration

**Create the desktop launcher:**
- Save as `~/.local/share/applications/brave-hardened.desktop`:

```bash
#!/bin/sh
############################################################################
# Brave hardened wrapper · v1.8 (20 May 2025)

############################################################################

# --------- Adjust this to the exit country of your proxy chain ----------
export TZ=America/New_York 

# --------- Proxy chain ---------------------------------------------------
P1="10.1.0.1:3128"
P2="10.0.0.2:3128"
export http_proxy="http://$P1"
export https_proxy="$http_proxy"
export ALL_PROXY="$http_proxy"

# ------------------------------------------------------------------------
exec brave \
  --no-first-run \
  --proxy-server="http://$P1;http://$P2" \
  --disable-quic \
  --dns-prefetch-disable \
  --disable-gpu --disable-gpu-rasterization --disable-accelerated-2d-canvas \
  --disable-3d-apis --disable-webgl --disable-webgpu --disable-webrtc \
  --disable-plugins --disable-plugins-discovery \
  --window-size=1920,1080 \
  --force-device-scale-factor=1 \
  --use-fake-device-for-media-stream \
  --lang=en-US,en;q=0.9 \
  --enable-features=StrictSiteIsolation,BlockInsecurePrivateNetworkRequests,ResistFingerprintingLetterboxing,V8NoJIT,V8ForceMemoryCage,MiraclePtr,FingerprintingClientRectRandomization \
  --disable-site-isolation-trials \
  --disable-features=AsyncDns,DnsOverHttps,UseDnsHttpsSvcbAlpn,EncryptedClientHello,ZstdContentEncoding,HighEntropyUserAgent,UserAgentClientHint,UserAgentClientHintFullVersionList,ReduceUserAgent,RawClipboard,\
BatteryStatus,BatteryStatusAPI,PreciseMemoryInfo,WebBluetooth,WebUSB,WebHID,WebSerial,WebNFC,WebGPU,WebRTC,GamepadButtonAxisEvents,ComputePressure,GenericSensor,GenericSensorExtraClasses,DeviceOrientation,DeviceMotionEvent,Accelerometer,Magnetometer,AmbientLightSensor,FontAccess,FontAccessChooser,BackForwardCache,UseWebP,DirectSockets,IdleDetection,FileSystemAccess,DigitalGoodsApi,SubresourceWebBundles,PrivateStateTokens,TrustTokens,WebXR,WebXRARModule,WebXRHandInput,WebCodecs,Portals,PaymentRequest,PaymentHandler,SecurePaymentConfirmation,SerialAPI,KeyboardLockAPI,ScreenWakeLock,WebShare,WebShareV2,WindowPlacement,ScreenDetailedInformation,LocalFontsAccess,BackgroundFetch,BackgroundSync,WebOTP,ContactPickerAPI,SpeechRecognition,WebSpeechSynthesisAPI,PdfOcr,OptimizationGuideHintDownloading,Prerender2,AudioServiceOutOfProcess,WebAudio \
 --enable-features=CrossOriginOpenerPolicyByDefault,CrossOriginEmbedderPolicyCredentialless \
  --disable-blink-features=MathMLCore,ClipboardCustomFormats,ClipboardUnsanitizedContent,AutomationControlled,ClipboardChangeEvent,ClipboardContentsId,ClipboardSvg,ClipboardItemWithDOMStringSupport,ClipboardEventTargetCanBeFocusedElement,IdleDetection,WebAudio \
  --disable-reading-from-canvas \
  --mask-webgl-vendor-and-renderer \
  --blink-settings=hardwareConcurrency=8,deviceMemory=4,timezone=$(cat /etc/timezone 2>/dev/null || echo ${TZ}),audioContextSampleRate=48000,disablePlugins=true \
  --deny-permission-prompts --no-referrers \
  --js-flags="--jitless --liftoff --no-expose-wasm --no-wasm-tier-up" \
  --ignore-certificate-errors \
  "$@"

```

**Make executable:**
```bash
chmod +x ~/.local/share/applications/brave-hardened.desktop
```

# CN privacy protocols
- gameplan: expose 443 on the pf for dynamic hosts only -> nginx/haproxy does 443to8080 -> singbox provides trojan-gfw/hysteria2 on 8080
  
- the singbox project can do hysteria2 and trojan-gfw:
```
git clone https://github.com/SagerNet/sing-box.git
```

- For Linux client(s):
```
# Clean Go cache and modules
go clean -cache
go clean -modcache
go mod tidy

# Build for Linux with reproducible build flags
GOOS=linux GOARCH=amd64 go build -a -trimpath -ldflags="-buildid=" -tags "with_quic with_utls with_reality_server" -o sing-box ./cmd/sing-box
# Or install globally
#go install -tags "with_quic with_utls with_reality_server" ./cmd/sing-box
```

- For OpenBSD server:
```
pkg_add go
# Clean Go cache and modules
go clean -cache
go clean -modcache
go mod tidy

# Build for OpenBSD with reproducible build flags
GOOS=openbsd GOARCH=amd64 go build -a -trimpath -ldflags="-buildid=" -tags "with_quic with_utls with_reality_server" -o sing-box ./cmd/sing-box
```
  
# Chose Nginx or HAProxy
- choose one or the other: HAProxy cannot proxy UDP in freemium as far as I know? via nginx you can (hysteria2)

- Installation and management:

```
# Install HAProxy
pkg_add nginx nginx-stream

# Enable and start HAProxy
rcctl enable nginx
rcctl start nginx

# Check status
rcctl check nginx

# Reload configuration
rcctl reload nginx
```

#### I.1. Nginx Stream Configuration
- Option1: Save as `/etc/nginx/nginx.conf`

```
worker_processes auto;
load_module modules/ngx_stream_module.so;

events {
    worker_connections 4096;
}
#trojan tcp - enabled
stream {
    upstream singbox_backend {
        server 127.0.0.1:8080; # Sing-box server listening on localhost:8080
    }

    # For TCP-based protocols (Trojan)
    server {
        listen 443; # TCP only
        proxy_pass singbox_backend;
    }
#hysteria udp - disabled
#    # For UDP-based protocols (Hysteria2)
#    server {
#       listen 443 udp; # UDP support required
#        proxy_pass singbox_backend;
#    }
}

```

#### I.1.1. HAProxy Configuration (Alternative for TCP-based protocols)


```
# Install HAProxy
pkg_add haproxy

# Enable and start HAProxy
rcctl enable haproxy
rcctl start haproxy

# Check status
rcctl check haproxy

# Reload configuration
rcctl reload haproxy
```

- Option2: Save as `/etc/haproxy/haproxy.cfg`

```
global
    log 127.0.0.1 local0 debug
    maxconn 1024
    chroot /var/haproxy
    uid 604
    gid 604
    daemon
    pidfile /var/run/haproxy.pid

defaults
    log global
    mode tcp  # Keep TCP mode for SSL passthrough
    option tcplog  # Log at the TCP level
    option dontlognull
    option redispatch
    retries 3
    maxconn 2000
    timeout connect 10s
    timeout client 300s
    timeout server 300s

frontend trojan_frontend
    bind *:443
    tcp-request inspect-delay 5s
    default_backend sing

backend sing
    mode tcp
    server trojan 127.0.0.1:8080
```

#### I.2. Trojan Protocol Configuration
##### I.2.1. Client Configuration


- Save as `client-config.json`

```
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "tls://1.1.1.1",
        "detour": "direct"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "sniff": true,
      "sniff_override_destination": true
    }
  ],
  "outbounds": [
    {
      "type": "trojan",
      "tag": "proxy",
      "server": "server.mydomain.net",
      "server_port": 443,
      "password": "password-long-123456-secure",
      "transport": {
        "type": "ws",
        "path": "/cdn/v3",
        "headers": {
          "Host": "server.mydomain.net"
        }
      },
      "tls": {
        "enabled": true,
        "server_name": "server.mydomain.net",
        "alpn": ["h2", "http/1.1"],
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

##### I.2.2. Server Configuration
- Save as `server-config.json`
```
{
  "log": {
    "level": "debug",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "127.0.0.1",
      "listen_port": 8080,
      "users": [
        {
          "name": "example",
          "password": "password-long-123456-secure"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/cdn/v3",
        "headers": {
          "Host": "server.mydomain.net"
        }
      },
      "tls": {
        "enabled": true,
        "certificate_path": "fullchain666.pem",
        "key_path": "privkey666.pem",
        "alpn": ["h2", "http/1.1"]
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
```
- run via `./sing-box run -c server-config.json`


#### I.3. Hysteria2 Protocol Configuration
##### I.3.1. Client Configuration
- Save as `client-config.json`
```
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "tls://1.1.1.1",
        "detour": "direct"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "sniff": true,
      "sniff_override_destination": true
    }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "up_mbps": 100,
      "down_mbps": 100,
      "tag": "proxy",
      "server": "server.mydomain.net",
      "server_port": 443,
      "obfs": {
        "type": "salamander",
        "password": "password-long-123456-secure-obfs"
      },
      "password": "password-long-123456-secure-hysteria",
      "tls": {
        "enabled": true,
        "server_name": "server.mydomain.net",
        "alpn": ["h3"]
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

##### I.3.2. Server Configuration
- Save as `server-config.json`
```
{
  "log": {
    "level": "debug",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "127.0.0.1",
      "listen_port": 8080,
      "users": [
        {
          "name": "example",
          "password": "password-long-123456-secure-hysteria"
        }
      ],
      "obfs": {
        "type": "salamander",
        "password": "password-long-123456-secure-obfs"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "fullchain666.pem",
        "key_path": "privkey666.pem",
        "alpn": ["h3"]
        "min_version": "1.3",
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
```
# optional: singbox runner

- B: here is an experimental runner script to be added to a: NON root user &&  NON root cornjob 
- `./runv6.sh` 
```
#!/bin/sh

# --- Define Variables ---

# Define the port to check
PORT="8080"

# Define the path to the sing-box binary and its name
BINARY_PATH="/home/myuser/sing-box"
BINARY_NAME="sing-box"
BINARY="${BINARY_PATH}/${BINARY_NAME}"

# Define the configuration file
CONFIG="/home/myuser/sing-box/config.json"

# Path to the directory containing the sing-box source code
SOURCE_DIR="/home/myuser/sing-box"

# Define how often to rebuild the binary (in days)
REBUILD_INTERVAL_DAYS="14"

# Define the temporary file to store the last build time (inside the source directory)
LAST_BUILD_TIME_FILE="${SOURCE_DIR}/.sb_last_build_time"

# Lock file to prevent concurrent executions
LOCK_FILE="${SOURCE_DIR}/.sb_cron_lock"

# Timeout for acquiring the lock (in seconds)
LOCK_TIMEOUT="60"

# Retry interval for port check (in seconds)
PORT_RETRY_INTERVAL="0.5"  # Significantly reduced retry interval
PORT_RETRY_COUNT="3"   # Increased retry count for more reliability

# Log file for sing-box output
LOG_FILE="${SOURCE_DIR}/sbo.log"

# Log file for script activity and stats
STATS_LOG_FILE="${SOURCE_DIR}/sbs.log"

# Variable to store if the script is running for the first time
FIRST_RUN=1

# --- End Variables ---

# Function to log messages
log() {
  echo "$(date +%Y-%m-%d_%H:%M:%S): $1" 
}

# Function to rebuild the sing-box binary
rebuild_binary() {
  echo "Rebuilding sing-box binary..."
  cd "${SOURCE_DIR}" || { echo "Error: Could not change directory to ${SOURCE_DIR}"; exit 1; }

  # Sanitize environment variables before running go commands
  export GOCACHE="$(pwd)/.cache/go-build"
  export GOMODCACHE="$(pwd)/.cache/go-mod"

  go clean -cache
  go clean -modcache
  go mod tidy
  GOOS=openbsd GOARCH=amd64 go build -a -trimpath -ldflags="-buildid=" -tags "with_quic with_utls with_reality_server" -o "${BINARY_NAME}" ./cmd/sing-box || { echo "Error: Go build failed"; exit 1; }
  # Move the newly built binary to the specified path
  mv "${SOURCE_DIR}/${BINARY_NAME}" "${BINARY_PATH}" || { echo "Error: Failed to move binary"; exit 1; }
  echo "Sing-box binary rebuilt and moved to ${BINARY}."

  # Update the last build time in the temporary file
  date +%s > "${LAST_BUILD_TIME_FILE}" || { echo "Error: Failed to update last build time"; exit 1; }
  unset GOCACHE
  unset GOMODCACHE
}

# Function to acquire the lock
acquire_lock() {
  start_time=$(date +%s)
  while [ -f "${LOCK_FILE}" ]; do
    PID=$(cat "${LOCK_FILE}")
    if ps -p "$PID" > /dev/null 2>&1; then
      echo "Another instance is already running (PID: $PID). Waiting..."
    else
      echo "Stale lock file found. Removing it."
      rm -f "${LOCK_FILE}"
      break
    fi

    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))
    if [ "$elapsed_time" -gt "${LOCK_TIMEOUT}" ]; then
      echo "Timeout waiting for lock. Exiting."
      exit 1
    fi
    sleep 5 # Wait before checking again
  done

  # Create a lock file
  echo "$$" > "${LOCK_FILE}" || { echo "Error: Failed to create lock file"; exit 1; }
}

# Function to release the lock
release_lock() {
  rm -f "${LOCK_FILE}"
}

# Trap signals to release the lock file on exit
trap "release_lock; exit" SIGHUP SIGINT SIGTERM

# Acquire the lock
acquire_lock

# Check if the last build time file exists
if [ ! -f "${LAST_BUILD_TIME_FILE}" ]; then
  echo "Last build time file not found. Creating it..."
  # If the file doesn't exist, create it and record the current time
  date +%s > "${LAST_BUILD_TIME_FILE}" || { echo "Error: Failed to create last build time file"; release_lock; exit 1; }
  chmod 600 "${LAST_BUILD_TIME_FILE}" # Limit permissions to owner only
fi

# Get the last build time from the file
LAST_BUILD_TIME=$(cat "${LAST_BUILD_TIME_FILE}")

# Check if LAST_BUILD_TIME is empty and set to 0 if it is
if [ -z "$LAST_BUILD_TIME" ]; then
  echo "LAST_BUILD_TIME is empty. Setting to 0."
  LAST_BUILD_TIME=0
fi

# Get the current time
CURRENT_TIME=$(date +%s)

# Calculate the rebuild interval in seconds
REBUILD_INTERVAL_SECONDS=$((REBUILD_INTERVAL_DAYS * 24 * 60 * 60))

# Calculate the time difference since the last build
TIME_DIFF=$((CURRENT_TIME - LAST_BUILD_TIME))

# Check if the rebuild interval has passed
if [ "$TIME_DIFF" -gt "${REBUILD_INTERVAL_SECONDS}" ]; then
  echo "Rebuild interval has passed. Rebuilding binary..."
  rebuild_binary
  # Pause for 3 minutes (180 seconds)
  echo "Pausing for 3 minutes..."
  sleep 180
else
  echo "Rebuild interval has not passed. Skipping binary rebuild."
fi

# Initialize the stats log file if it doesn't exist
if [ ! -f "${STATS_LOG_FILE}" ]; then
  echo "Script Runs,Restarts" > "${STATS_LOG_FILE}"
  echo "0,0" >> "${STATS_LOG_FILE}"
fi

# Read the existing stats from the log file
STATS=$(head -n 1 "${STATS_LOG_FILE}")
RUN_COUNT=$(awk -F, '{print $1}' "${STATS_LOG_FILE}" | tail -n 1)
RESTART_COUNT=$(awk -F, '{print $2}' "${STATS_LOG_FILE}" | tail -n 1)

# Function to check if sing-box is running and listening on the port
is_singbox_running() {
  # Use fstat to find processes listening on the port
  FSTAT_OUTPUT=$(fstat -n | grep ":${PORT}")
  PS_OUTPUT=$(ps aux | grep "${BINARY_NAME}" | grep -v grep)

  # Determine the current state of sing-box
  if [ -n "$FSTAT_OUTPUT" ] && [ -n "$PS_OUTPUT" ]; then
    CURRENT_SINGBOX_STATE="running"
  else
    CURRENT_SINGBOX_STATE="stopped"
  fi

 #Add Logging here for the "is_singbox_running()".
 if [ "$FIRST_RUN" -eq 1 ]; then
	echo "--- Running checks ---"
  echo "  fstat output: $FSTAT_OUTPUT"
  echo "ps -ef output:$PS_OUTPUT"
  FIRST_RUN=0
  fi
    #Added it now here, it looks like the 5 to 6 lost this ability to detect it (we need a 0 code if true, but for it you would need another PS)
        if [ -n "$FSTAT_OUTPUT" ] && [ -n "$PS_OUTPUT" ]; then
    return 0
        else
         return 1
        fi
  }

# Check if sing-box is listening on the port and retry
for i in $(seq 1 "${PORT_RETRY_COUNT}"); do
  if is_singbox_running; then
      :
    release_lock
    exit 0  # Exit successfully - sing-box is running
  else
    sleep "${PORT_RETRY_INTERVAL}"
  fi
done

# Increment the run counter
RUN_COUNT=$((RUN_COUNT + 1))

# Increment the restart counter (since we're starting it)
RESTART_COUNT=$((RESTART_COUNT + 1))

# Update the stats log file
echo "$RUN_COUNT,$RESTART_COUNT" > "${STATS_LOG_FILE}"

echo "sing-box is not running after ${PORT_RETRY_COUNT} attempts. Starting it."

# Run the sing-box binary, properly detached
(
  cd "${BINARY_PATH}" || exit 1
  ./"${BINARY_NAME}" run -c "${CONFIG}" > "${LOG_FILE}" 2>&1 &
)
echo "Starting sing-box detached (logging to ${LOG_FILE})."

# Release the lock
release_lock

exit 0

```

# alternative1: when in doubt SSH-VPN

```
shuttle --dns -NHr root@myserver-ip.ip:443 0/0 #
sshuttle --dns -NHr username@myserver-ip.ipinfo:443 10.0.0.0/24 #
```

# alternative2:  SSH -D
```
ssh -D 3128 my-server
```

# optional: debugging commands section

```bash
# Show dynamic hosts table contents
pfctl -t dynamic_hosts -T show

# Show ASN table contents  
pfctl -t asn -T show

# Show Cloudflare IPs table
pfctl -t cloudflare_ips -T show

# Test PF configuration syntax
pfctl -nf /etc/pf.conf

# Reload PF rules
pfctl -f /etc/pf.conf

# Show PF status and statistics
pfctl -s info
pfctl -s states
pfctl -s rules

# Show blocked traffic
pfctl -s states | grep CLOSED

# Monitor PF logs (if pflog enabled)
tcpdump -n -e -ttt -i pflog0

# Monitor specific traffic patterns
tcpdump -n -e -ttt -i pflog0 host <IP_ADDRESS>
tcpdump -n -e -ttt -i pflog0 port 51820  # For WireGuard

# Monitor interface traffic directly
tcpdump -ni vio0 port 443 or port 8080

# Show active PF states with verbose output
pfctl -ss

# Show rules with verbose statistics
pfctl -v -sr
```


```bash
# Start WireGuard interface
sh /etc/netstart wg0

# Stop WireGuard interface  
ifconfig wg0 destroy

# Restart WireGuard interface
ifconfig wg0 destroy && sh /etc/netstart wg0

# Check interface status
ifconfig wg0
wg show wg0

# View WireGuard configuration
wg showconf wg0
```

```bash

# Monitor firewall update logs
tail -f /usr/local/firewall_update.log

# Monitor ASN update logs  
tail -f /usr/local/asn_update.log

# Monitor system messages for phone-ip-check
tail -f /var/log/messages | grep "phone-ip-check"

# Monitor system messages for pf-updater
tail -f /var/log/messages | grep "pf-updater"

# Check current dynamic IPs
cat /usr/local/gotten-para

# Check current ASN list
cat /usr/local/asn_list.txt

```

```bash
# Check WireGuard interface status
ifconfig wg0

# Show WireGuard configuration
wg showconf wg0

# Show WireGuard 
wg show

# Check if using kernel implementation
ifconfig wg0 | grep "groups: wg"

# Monitor WireGuard traffic
wg show wg0 transfer


# Monitor WireGuard process (if userspace)
top -d1 | grep wg

# Multiple WireGuard interface management
sh /etc/netstart wg0

```

```bash
# Check routing table for VPN network
route -n show -inet | grep 10.0.0

# Check interface routing
route -n show -inet -interface wg0

dig @10.0.0.1 example.com
dig @10.0.0.1 +tls example.com
dig @10.0.0.1 +https example.com
```

```bash
# Check Unbound status
rcctl status unbound

# Check Unbound configuration
unbound-checkconf

# Monitor Unbound logs
tail -f /var/log/daemon | grep unbound

# Check DNS cache statistics
unbound-control stats_noreset
```

```bash
# Check container status
podman ps -a --filter name=adguard-home

# View container logs
podman logs adguard-home

```

```bash
# Check Squid status
rcctl status squid

# Test Squid configuration
squid -k parse

```

```bash
# Check all enabled services
rcctl ls on

# Monitor system resources
top -d1
vmstat 1
iostat 1

# Check network connections
netstat -an | grep LISTEN
netstat -rn
```

```bash
# Test DNS resolution
nslookup example.com
host example.com

# Test specific ports
nc -zv example.com 443

# Monitor network traffic
tcpdump -i vio0 host example.com
tcpdump -i wg0
```

```bash
traceroute example.com

# Monitor interface statistics
netstat -i
systat ifstat

# Check ARP table
arp -a

# Monitor bandwidth usage
systat netstat
```

```bash

top -d1

# Disk I/O
iostat -w 1

# Network statistics
systat netstat

# Process monitoring
ps aux | grep -E "(squid|unbound|wg)"

# Memory usage details
vmstat -m

# PF blocked connections
pfctl -s states | grep CLOSED

# Shutdowns
/sbin/halt -p 

shutdown -r now 
```

good luck

future ideas:
- port knocking
- nginx cert auth at start requirement
