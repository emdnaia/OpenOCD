# OpenOCD

This project gets you:

- OpenBSD: Static filtering of static IPs for SSH
- OpenBSD: Dynamic filtering of dynamic IPs for VPN (Wireguard)
- Linux: Dynamic filtering of dynamic IPs for VPN (Wireguard)
- OpenBSD: Encrypted DNS via ODoH / DoT via Unbound + DNScrypt
- OpenBSD: Adblocker skript to pull adlists for Unbound

### Some steps

1. **Initial Setup:** Start by configuring the OpenBSD gateway with the provided PF configuration to set up initial firewall rules.
2. **Dynamic IP Script:** Implement the dynamic IP update script to maintain an up-to-date whitelist of IPs that can access the VPN.
3. **Cron Configuration:** Schedule the provided cron jobs to automate the updating and maintenance tasks.
4. **DNS Encryption:** Follow the DNS setup instructions to encrypt DNS queries, using either DoT or ODoH.
5. **Ad Blocking:** Set up the ad blocker script to filter out unwanted ads.

### Detailed Configuration Scripts and Commands

- **Dynamic IP Update Script (`getpara.sh`)**: This script resolves the current IP address for a specified FQDN and updates the PF table with any changes.
  
- **PF Configuration (`pf.conf`)**: Includes rules for blocking, allowing SSH from specific IPs, handling Wireguard traffic, and default deny policies.

- **Cron Jobs**: Automates system updates, VPN renewals, and the dynamic IP update script. If on the go, reduce the cronjob size to refreshing every 2-5 minutes on `getpara.sh`, like this you can unlock a laptop on a hotspot in a train. The laptop would only need a dynamic dns client unlocking the public IP, which is also set to a maximum number kicking off the older ones.

- **DNS Configuration**: Setup guides for DoT and ODoH, including configuration changes for `dnscrypt-proxy`.

- **Ad Blocker Script**: Instructions and script for setting up ad blocking on OpenBSD using Unbound.

#### Some OpenBSD Cronjobs right away
-  add via `crontab -e`  
```
@reboot /bin/sleep 30 && /usr/local/bin/wg-quick up wg0
@reboot /bin/sleep 30 && /usr/sbin/rcctl restart unbound

30 13 * * * /usr/sbin/syspatch -c 
32 13 * * * /usr/sbin/syspatch
35 13 * * * /usr/sbin/pkg_add -u

@reboot /bin/sleep 30 && /usr/local/getpara.sh
0 0,12 * * * /usr/local/getpara.sh

2 0 * * * /usr/sbin/rcctl restart unbound
```
### Firewall: OpenBSD PF rules for static & dynamic ips

- You edit the pf rules on ` /etc/pf.conf ` and check via  `pfctl -nf /etc/pf.conf` and  load them via  `pfctl -f  /etc/pf.conf` | non - webserver example
- version A (more secure)
```
# $OpenBSD: pf.conf,v 1.55 2017/12/03 20:40:04 sthen Exp $
#
# See pf.conf(5) and /etc/examples/pf.conf

# Configuration Variables
dynamic_hosts_file="/usr/local/gotten-para"  # Location for dynamic hosts
wireguard_port="51820"                        # Your WireGuard VPN port
wireguard_net="10.0.0.0/24"                 # Your WireGuard VPN network
ssh_allowed_ips="{6.6.6.6/32, 7.7.7.7/32}"  # IPs allowed for SSH
wireguard_iface="wg0"                       # WireGuard interface identifier

# Block Ipv6 - remember hotspot leakage
block quick inet6

set skip on lo

# Block all incoming on vio0 but allow outgoing
block in on vio0 all

# NAT for outgoing traffic
match out on egress inet from !(egress:network) to any nat-to (egress:0)

# Allow SSH from specified IPs
pass in on vio0 proto tcp from $ssh_allowed_ips to (vio0) port 22 keep state
pass out quick on vio0 keep state

# Allow only IPs from <dynamic_hosts> to access WireGuard port on vio0
pass in on vio0 proto udp from <dynamic_hosts> to any port $wireguard_port keep state
pass out on vio0 proto udp to <dynamic_hosts> port $wireguard_port keep state

# Allow all on WireGuard interface
pass in on $wireguard_iface from $wireguard_net to any
pass out on $wireguard_iface from any to $wireguard_net

# By default, do not permit remote connections to X11
block return in on ! lo0 proto tcp to port 6000:6010

# Port build user does not need network
block return out log proto {tcp udp} user _pbuild
```


- hypervisor forward example to -> pf firewall filtering forward to -> webserver
- hypervisor forward via iptables:

```
## Variables
real_adapter_name="YOUR_ADAPTER_NAME"  # Replace this with the actual adapter name like eth0 or any placeholder
backend_server_ip="10.0.0.33"  # New IP instead of 10.9.3.33

## Forward port 443 from the real adapter to backend server on port 443
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $backend_server_ip:443
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 443 -j DNAT --to $backend_server_ip:443

## Forward port 80 from the real adapter to backend server on port 80
post-up iptables -t nat -A PREROUTING -i $real_adapter_name -p tcp --dport 80 -j DNAT --to $backend_server_ip:80
post-down iptables -t nat -D PREROUTING -i $real_adapter_name -p tcp --dport 80 -j DNAT --to $backend_server_ip:80
```

- version B (with webserver): pf then forwards to webserver that can be accessed from dynamic ips + static ips
- dns is internal and can connect to the vpn
```
# $OpenBSD: pf.conf,v 1.55 2017/12/03 20:40:04 sthen Exp $
#
# See pf.conf(5) and /etc/examples/pf.conf

# Configuration Variables
dynamic_hosts_file="/usr/local/gotten-para"  # Location for dynamic hosts
wireguard_port="51820"                       # Your WireGuard VPN port
wireguard_net="10.0.0.0/24"                  # Your WireGuard VPN network
ssh_allowed_ips="{6.6.6.6/32, 7.7.7.7/32}"   # IPs allowed for SSH
wireguard_iface="wg0"                        # WireGuard interface identifier
final_backend_server="10.0.0.207"            # Final backend server IP
internal_dns_server="10.0.0.34"              # Internal DNS server IP
gateway_server="10.0.0.1"                    # Gateway server IP

# Block IPv6
block quick inet6

set skip on lo  # Skip loopback interface

# ---- Security Rules ----

# Block all inbound traffic except for explicitly allowed rules
block in on vio0 all

# Block X11 connections (optional security)
block return in on ! lo0 proto tcp to port 6000:6010

# Block network access for _pbuild user
block return out log proto {tcp udp} user _pbuild

# ---- NAT for Outgoing Traffic ----

# NAT outgoing traffic from non-egress networks (LAN/WireGuard)
match out on egress inet from !(egress:network) to any nat-to (egress:0)

# NAT for outgoing traffic from WireGuard network to external clients
match out on egress inet from $wireguard_net to any nat-to (egress:0)

# ---- Port Forwarding and Traffic Handling ----

# Allow access to port 80 (HTTP) from dynamic IPs and ssh_allowed_ips, and forward traffic to internal server
pass in log on vio0 proto tcp from <dynamic_hosts> to any port 80 rdr-to $final_backend_server port 80 keep state
pass in log on vio0 proto tcp from $ssh_allowed_ips to any port 80 rdr-to $final_backend_server port 80 keep state

# Allow access to port 443 (HTTPS) from dynamic IPs and ssh_allowed_ips, and forward traffic to internal server
pass in log on vio0 proto tcp from <dynamic_hosts> to any port 443 rdr-to $final_backend_server port 443 keep state
pass in log on vio0 proto tcp from $ssh_allowed_ips to any port 443 rdr-to $final_backend_server port 443 keep state

# ---- WireGuard-Specific Rules for Internal Traffic ----

# Allow intra-WireGuard traffic (e.g., from WireGuard clients accessing internal server)
pass in on $wireguard_iface proto tcp from $wireguard_net to $final_backend_server keep state
pass out on $wireguard_iface proto tcp from $final_backend_server to $wireguard_net keep state

# ---- SSH and DNS Access Rules ----

# Allow SSH from gateway_server
pass in on vio0 proto tcp from $gateway_server to (vio0) port 22 keep state
pass out quick on vio0 keep state

# Allow DNS requests from allowed SSH IPs
pass in on vio0 proto {udp tcp} from $ssh_allowed_ips to any port 53 keep state
pass out on vio0 proto {udp tcp} from any to any port 53 keep state

# ---- WireGuard-Specific DNS Rules ----

# Allow DNS requests from WireGuard clients (on WireGuard network) to internal DNS server
pass in on $wireguard_iface proto udp from $internal_dns_server to $wireguard_net port 53 keep state
pass out on $wireguard_iface proto udp from $wireguard_net to $internal_dns_server port 53 keep state

# ---- WireGuard-Specific Rules for External Access ----

# Only allow WireGuard access from dynamic IPs
pass in on vio0 proto udp from <dynamic_hosts> to any port $wireguard_port keep state
pass out on vio0 proto udp from (vio0) port $wireguard_port to <dynamic_hosts> keep state

# Allow DNS server to access WireGuard for traffic
pass in on vio0 proto udp from $internal_dns_server to (vio0) port $wireguard_port keep state
pass out on vio0 proto udp from (vio0) port $wireguard_port to $internal_dns_server keep state

# Allow all traffic between WireGuard interface (wg0) and WireGuard network
pass in on $wireguard_iface from $wireguard_net to any
pass out on $wireguard_iface from any to $wireguard_net

# ---- Ensure Return Traffic ----

# Ensure return traffic from internal server to WireGuard clients is handled properly
pass in on $wireguard_iface proto tcp from $final_backend_server to any keep state
pass out on vio0 proto tcp from $final_backend_server to any keep state
```

### Skript to add the dynamic hosts
- Important: All your clients will need to get FQDNs, and you can do that by adding for example containers in your home, work etc, that use tools like `ddclient` + any DYNDNS-hoster.
- Next, *Ensure you replace `hoster1 + hoster2` with your actual domains to allow dynamic access from.*
- The script below will access the FQDN and add it to the firewall ruletable for access.

I've deployed the following script on `/usr/local/getpara.sh` it creates `temp_gotten_para` as well as `gotten-para` which contains the dynamic IPs to be added to the firewall for access.

```sh
#!/bin/sh

# FQDNs
FQDN1="myhost1.hoster1.org"
FQDN2="myhost2.hoster2.org"

# Define variables
WORK_DIR="/usr/local"
TEMP_IP_FILE="$WORK_DIR/temp_gotten_para"
FINAL_IP_FILE="$WORK_DIR/gotten-para"
LOG_FILE="$WORK_DIR/firewall_update.log"
MAX_IP_COUNT=2  # Adjusted if needed to allow more IPs
IP_RETENTION_DAYS=2

# Setup and cleanup environment
if [ ! -f "$TEMP_IP_FILE" ]; then
    echo "Creating $TEMP_IP_FILE as it does not exist."
    touch "$TEMP_IP_FILE"
fi

# Function to log messages with timestamps
log() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

# Function to validate an IP address
is_valid_ip() {
    local ip=$1
    if echo "$ip" | grep -Eq "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        return 0
    else
        return 1
    fi
}

# Function to resolve IP addresses and avoid duplicates
resolve_ip() {
    local FQDN=$1
    log "Resolving IP address for $FQDN"
    # Resolve the current IP address of the FQDN
    CURRENT_IP=$(dig +short $FQDN | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    CURRENT_TIMESTAMP=$(date +%s)

    # Exit if no valid IP is resolved
    if [ -z "$CURRENT_IP" ] || ! is_valid_ip "$CURRENT_IP"; then
        log "No valid IP address found for $FQDN"
        return
    fi

    # Check if the IP already exists in the TEMP_IP_FILE to avoid duplicates
    if ! grep -q "$CURRENT_IP" "$TEMP_IP_FILE"; then
        # Append current IP with timestamp to TEMP_IP_FILE for processing
        echo "$CURRENT_TIMESTAMP $CURRENT_IP" >> "$TEMP_IP_FILE"
        log "Added IP $CURRENT_IP to $TEMP_IP_FILE"
    else
        log "IP $CURRENT_IP already exists in $TEMP_IP_FILE, not adding again."
    fi
}

# Ensure FINAL_IP_FILE exists
if [ ! -f "$FINAL_IP_FILE" ]; then
    echo "Creating $FINAL_IP_FILE as it does not exist."
    touch "$FINAL_IP_FILE"
fi

# Resolve IPs for both FQDNs
resolve_ip $FQDN1
resolve_ip $FQDN2

# Process TEMP_IP_FILE to ensure uniqueness, limit the number of IPs, and consider the retention period
log "Processing $TEMP_IP_FILE to update $FINAL_IP_FILE"
awk -v max_count=$MAX_IP_COUNT -v retention_days=$IP_RETENTION_DAYS -v current_time=$(date +%s) '{
    timestamp = $1
    ip = $2
    if (!seen[ip]++ && (current_time - timestamp) <= (retention_days * 86400)) {
        print ip
        if (++count >= max_count) exit
    }
}' "$TEMP_IP_FILE" | sort -u | tail -n $MAX_IP_COUNT > "$FINAL_IP_FILE"

# Cleanup old entries from TEMP_IP_FILE
log "Cleaning up old entries from $TEMP_IP_FILE"
awk -v current_time=$(date +%s) -v retention_days=$IP_RETENTION_DAYS '{
    timestamp = $1
    if ((current_time - timestamp) <= (retention_days * 86400)) {
        print $0
    }
}' "$TEMP_IP_FILE" > "${TEMP_IP_FILE}.tmp" && mv "${TEMP_IP_FILE}.tmp" "$TEMP_IP_FILE"

# Check if there are any changes
if [ "$(wc -l < "$FINAL_IP_FILE")" -eq 0 ]; then
    log "No changes."
else
    # Reload the PF table with the updated IP list
    log "Reloading PF table 'dynamic_hosts' with updated IP list from $FINAL_IP_FILE"
    pfctl -t dynamic_hosts -T replace -f "$FINAL_IP_FILE" && log "PF table 'dynamic_hosts' reloaded with updated IP list."

    # Output the contents of the PF table
    log "Contents of PF table 'dynamic_hosts':"
    pfctl -t dynamic_hosts -T show >> "$LOG_FILE"
fi

# Log completion message
log "Firewall update complete."
```
### Wireguards

- After you installed the package via `pkg_add wireguard-tools`,your gateways `wg0.conf` looks like this on `/etc/wireguard/wg0.conf`and you can trigger restarts for the interface like `wg-quick down wg0 && sleep 5 && wg-quick up wg0`.
- You generate client priv and pub keys via ` sh -c 'umask 077; wg genkey | tee privatekey | wg pubkey > publickey'`
- You can have your entire infrastructure within nested wireguards, increasing trust per interface

Server side:
```
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = gateways-private-key

[Peer]
PublicKey = publickey-client1
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = publickey-client-2
AllowedIPs = 10.0.0.3/32
```
Client side:

```
[Interface]
PrivateKey = client-private-key
#DNS=10.0.0.1
Address = 10.0.0.2/24
#ListenPort=

[Peer]
PublicKey =  server-pubkey
AllowedIPs = 10.0.0.0/24
Endpoint = public-gateway-ip:51820
PersistentKeepalive = 15
```

- Congrats, You arere already done at this point, you only allow static IPs to connect, everything else is inside a VPN tunnel that only allows connecting from whitelisted fqdns!
- Always room for improvement, add encrypted DNS, as well as an addblocker
  
### Optional DNS 
#### Option 1: ODOH via Cloudflare
- You work on `/etc/dnscrypt-proxy.toml`
- Use the Guide from here:  SwaroopGiri: (https://github.com/SwaroopGiri/Pihole-with-Anonymized-ODOH)
- The DNScrypt runs at 127.0.0.1@54, which Unbound at 127.0.0.1@53 will just forward requests to, while only accessible from Wireguard clients:

- Here is how you add the dnscrypt proxy package and check paths, plus how to do restarts and enabling of it
```
pkg_add dnscrypt-proxy
pkg_info -L dnscrypt-proxy
...
rcctl enable dnscrypt_proxy
rcctl restart unbound
rcctl restart dnscrypt_proxy
```
  - Important settings from the guide :
```
server_names = ['odoh-cloudflare']
odoh_servers = true
require_dnssec = true   
require_nofilter = true # this parameter depends on your relay selected next
cache = false   
```
- Enable sources:
```
[sources.odoh-servers]
   urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md', 'https://ipv6.download.dnscrypt.info/resolvers-list/v3/odoh-servers.md']
   cache_file = 'odoh-servers.md'
   minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
   refresh_delay = 24
   prefix = ''
[sources.odoh-relays]
   urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md', 'https://ipv6.download.dnscrypt.info/resolvers-list/v3/odoh-relays.md']
   cache_file = 'odoh-relays.md'
   minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
   refresh_delay = 24
   prefix = ''
```
- Select relays via https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md

```
routes = [
     { server_name='odoh-cloudflare', via=['odohrelay-your-pick1', 'oodohrelay-your-pick2'] },
     { server_name='odohrelay-koki-ams', via=['odohrelay-koki-ams', 'odohrelay-koki-bcn'] }
 ]
```
#### Unbound for ODoH
- We use Unbound for DNs, the config is at ` /var/unbound/etc/unbound.conf `
- The config is as simple as forwarding to the dnscrypt, uncomment the rest

```
server:
	interface: 0.0.0.0@53
	do-ip6: no
	access-control: 10.0.0.0/24 allow
	access-control: 0.0.0.0/0 refuse
	access-control: ::0/0 refuse
	
	forward-zone:
    		name: "."
        	forward-addr: 127.0.0.1@54

#Include the blocklist for ads
include: "/home/lowpriv_user/blacklist.conf"
```
  
#### Option 2: DOT via Quad9
- We use Unbound for DoT and can skip dnscrypt, the config is at ` /var/unbound/etc/unbound.conf `
```
# example config from: https://nurdletech.com/linux-notes/dns/unbound.html
server:
	interface: 0.0.0.0@53
	#interface: 127.0.0.1@5353	# listen on alternative port
	#interface: ::1
	do-ip6: no
#	do-udp: yes
#	do-tcp: yes
	
	auto-trust-anchor-file: "/var/unbound/db/root.key"
	tls-cert-bundle: "/etc/ssl/cert.pem"

	access-control: 10.0.0.0/24 allow
	access-control: 0.0.0.0/0 refuse
	access-control: ::0/0 refuse

	forward-zone:
    		name: "."
		forward-tls-upstream: yes		# use DNS-over-TLS forwarder
# 	hide-identity: yes
#	hide-version: yes

        # Cloudflare pick
	#	forward-addr: 1.1.1.1@53
	#	forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
  	#       forward-addr: 1.1.1.1@853#cloudflare-dns.com
 	#	forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com
    	#	forward-addr: 1.0.0.1@853#cloudflare-dns.com
        # Quad9 pick
	       forward-addr: 2620:fe::fe@853#dns.quad9.net
	       forward-addr: 9.9.9.9@853#dns.quad9.net
	       forward-addr: 2620:fe::9@853#dns.quad9.net
	       forward-addr: 149.112.112.112@853#dns.quad9.net

 # Include the blocklist for ads
include: "/home/lowpriv_user/blacklist.conf"
```
- In case you still need to generate the key:
```
unbound-anchor -a /var/unbound/db/root.key
```

#### Optional Linux side for dynamic IP adding

- Here is the same  `/usr/local/getpara.sh` but adjusted for Linux:
```
#!/bin/bash

# FQDNs
FQDN1="myhost1.myhoster1.org"
FQDN2="myhost2.myhoster2.org"

# Variables
# Directory for log and temporary files
WORK_DIR="/usr/local"
TEMP_IP_FILE="$WORK_DIR/temp_gotten_para"
FINAL_IP_FILE="$WORK_DIR/gotten-para"
LOG_FILE="$WORK_DIR/firewall_update.log"

MAX_IP_COUNT=3  # Adjust if needed to allow more IPs
IP_RETENTION_DAYS=6
IP_SET_NAME="dynamic_hosts"
WG_ZONES=("wireguard0" "public")  # List of WireGuard zones
WG_PORT="51820"  # WireGuard port, adjust as needed

# Setup and cleanup environment
> "$TEMP_IP_FILE"  # Clear temporary file
> "$FINAL_IP_FILE"  # Clear final IP file
touch "$LOG_FILE"  # Ensure log file exists
exec 3>&1 1>>"$LOG_FILE" 2>&1  # Redirect stdout and stderr to log file

# Function to log messages with timestamps
log() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") - $1"
}

# Function to execute commands and log their output without using eval
execute_command() {
    echo "Executing command: ${*}" >&3  # Log command to LOG_FILE
    "${@}"
    local status=$?
    if [ $status -ne 0 ]; then
        log "ERROR: Failed to execute: ${*}"
        exit $status
    else
        log "SUCCESS: Executed: ${*}"
    fi
}

# Function to ensure files exist
ensure_files_exist() {
    touch "$1" 2>/dev/null || {
        log "Failed to touch $1. Check permissions."
        exit 1
    }
}

# Ensure temporary and final IP files exist
ensure_files_exist "$TEMP_IP_FILE"
ensure_files_exist "$FINAL_IP_FILE"

resolve_ip() {
    local FQDN=$1
    local CURRENT_IP=$(dig +short $FQDN | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}$')
    local CURRENT_TIMESTAMP=$(date +%s)

    if [ -z "$CURRENT_IP" ]; then
        log "No valid IP address found for $FQDN"
        return
    fi

    # Check if the same IP with the same timestamp already exists
    if ! grep -q "$CURRENT_TIMESTAMP $CURRENT_IP" "$TEMP_IP_FILE"; then
        echo "$CURRENT_TIMESTAMP $CURRENT_IP" >> "$TEMP_IP_FILE"
    else
        log "Duplicate IP entry for $CURRENT_IP at $CURRENT_TIMESTAMP skipped"
    fi
}

# Resolve IPs for both FQDNs
resolve_ip $FQDN1
resolve_ip $FQDN2

# Process TEMP_IP_FILE to ensure uniqueness, limit the number of IPs, and consider the retention period
awk -v max_count=$MAX_IP_COUNT -v retention_days=$IP_RETENTION_DAYS -v current_time=$(date +%s) '{
    ip = $2
    timestamp = $1
    if (!seen[ip]++ && (current_time - timestamp) <= (retention_days * 86400)) {
        print ip
        if (++count >= max_count) exit
    }
}' "$TEMP_IP_FILE" | sort -u | tail -n $MAX_IP_COUNT > "$FINAL_IP_FILE"

# Log current IPs before deletion
log "Current IP set entries before deletion:"
firewall-cmd --ipset=$IP_SET_NAME --get-entries >> "$LOG_FILE"

# Update the firewalld IP set
log "Deleting and recreating IP set"
execute_command firewall-cmd --permanent --delete-ipset=$IP_SET_NAME 2>/dev/null
execute_command firewall-cmd --permanent --new-ipset=$IP_SET_NAME --type=hash:ip

# Re-load current IPs after changes
mapfile -t current_ips < <(firewall-cmd --ipset=$IP_SET_NAME --get-entries)

# Add new IPs
log "Adding IPs to the new IP set"
for ip in $(cat "$FINAL_IP_FILE"); do
    if [[ ! " ${current_ips[*]} " =~ " ${ip} " ]]; then
        execute_command firewall-cmd --permanent --ipset=$IP_SET_NAME --add-entry=$ip
    fi
done

# Update WireGuard rules for each zone
for zone in "${WG_ZONES[@]}"; do
    log "Updating WireGuard rules for zone: $zone"
    if ! firewall-cmd --permanent --zone="$zone" --query-rich-rule="rule family='ipv4' source ipset='$IP_SET_NAME' port port='$WG_PORT' protocol='udp' accept"; then
        execute_command firewall-cmd --permanent --zone="$zone" --add-rich-rule="rule family='ipv4' source ipset='$IP_SET_NAME' port port='$WG_PORT' protocol='udp' accept"
    fi
done

# Reload firewall to apply changes
execute_command firewall-cmd --reload

log "Firewall and WireGuard rules updated with latest IPs."

# Cleanup and close logging
exec 1>&3 3>&-

echo "Firewall update complete. See $LOG_FILE for details."
```
- In case we wanna confirm para entries:
```
firewall-cmd --ipset=dynamic_hosts --get-entries
```
- In case we wanna remove entries:
```
firewall-cmd --ipset=dynamic_hosts --get-entries | xargs -I{} firewall-cmd --permanent --ipset=dynamic_hosts --remove-entry={} && firewall-cmd --reload
```
- We need to also add this to the cronjob of the Linux server, for example on reboot and 12 hours:
```
@reboot /bin/sleep 30 && /usr/local/getpara.sh
0 0,12 * * * /usr/local/getpara.sh
```

#### Optional Addblocking
- Reference on the top to the original one, I only care about OpenBSD and want this to be ran on a lowpriv user for it!
- Please add your own custom lists, I prefer to not show mine!
- You could save this at ` /home/lowpriv_user/blocklister.sh` with an own account on a user named `lowpriv_user`
- Get the lowpriv_user to run this daily, unbound has an `include` for it.
  
```
#!/bin/sh


# This script is based on the version of 2020 Slawomir Wojciech Wojtczak (vermaden) found here:
# https://github.com/vermaden/scripts/blob/master/unbound-blacklist-fetch-huge.sh

# My version is smaller and doesn't need to be ran as root
# I am not leaking my favourite ad lists, there are plenty good ones


# SETTINGS
TYPE=always_nxdomain
TEMP="/home/lowpriv_user/unbound_temp"
ECHO=1
FILE="/home/lowpriv_user/blacklist.conf"
TEMP_FILE="/lowpriv_user/temp_blacklist.conf"

# Create temp directory
[ "${ECHO}" != "0" ] && echo "mkdir: create '${TEMP}' temp dir"
mkdir -p ${TEMP}

# FETCH add lists you can add multiple you like or use pihole or adguard, but why not make some pre filtering on a low priv user

[ "${ECHO}" != "0" ] && echo "fetch: ${TEMP}/lists-domains"
curl -s 'https://your-1st-list.txt' \
     'https://your-snd-list.txt' \
     'https://your-trd-list.txt' \
     'https://your-fourth-list.txt' \
     'https://your-fifth-list.txt/ ' \
     > "${TEMP}/lists-domains"


# GENERATE CONFIG
[ "${ECHO}" != "0" ] && echo "echo: add '${FILE}' header"
echo 'server:' > ${FILE}

[ "${ECHO}" != "0" ] && echo "echo: add '${FILE}' rules"
cat "${TEMP}/lists-domains" \
  | grep -v '^(.)*#' -E \
  | grep -v '^#' \
  | grep -v '^$' \
  | grep -v '^!' \
  | awk '{print $1}' \
  | sed -e s/$'\r'//g \
        -e 's/^\|\|//' \
        -e 's/\^$//' \
        -e 's/^\|//' \
        -e '/^\/.*\/$/d' \
        -e '/https?:\/\//d' \
        -e 's|\.$||g' \
        -e 's|^\.||g' \
  | grep -v -e '127.0.0.1' \
            -e '0.0.0.0' \
            -e '255.255.255.255' \
            -e '::' \
            -e 'localhost' \
            -e 'localhost.localdomain' \
            -e 'ip6-localhost' \
            -e 'ip6-loopback' \
            -e 'ip6-localnet' \
            -e 'ip6-mcastprefix' \
            -e 'ip6-allnodes' \
            -e 'ip6-allrouters' \
            -e 'broadcasthost' \
            -e 'ff02::' \
  | tr '[:upper:]' '[:lower:]' \
  | tr -d '\r' \
  | tr -d '#' \
  | sort -u \
  | sed 1,2d \
  | while read I; do
      echo "local-zone: \"${I}\" ${TYPE}"
    done > ${TEMP_FILE} 2>"${TEMP}/debug-errors.txt"

# Remove duplicate entries and ensure file starts with 'server:'
echo 'server:' > ${FILE}
sort ${TEMP_FILE} | uniq >> ${FILE}
rm -f ${TEMP_FILE}

# REMINDER FOR MANUAL ACTION
[ "${ECHO}" != "0" ] && echo "Reminder: Manually check the unbound configuration with 'unbound-checkconf ${FILE}' and, if valid, restart the unbound service with appropriate permissions."

# CLEAN
[ "${ECHO}" != "0" ] && echo "rm: remove '${TEMP}' temp dir BUT keep debug files"
rm -rf ${TEMP}/lists-domains

# UNSET
unset FILE
unset TYPE
unset TEMP
unset ECHO
unset UNAME
```
- This should be now ran as the lowpriv_user in a crontab for getting the blocklists:
```
0 0 * * * /home/lowpriv_user/blocklister.sh
```
Much love if you read until here
