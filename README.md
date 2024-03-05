# OpenOCD

This project gets you:

1) Only allowing whitelisted STATIC gateway IPs to access -> gateways | the static public ip has to match
   
2a) Only allowing whitelisted DYNAMIC IPs to access VPNs -> clients, other server | the dynamically gotten public ip has to match
2b) Linux version of 2a

3) Encrypted DNS via ODOH / DOT via Unbound + DNScrypt
4) Adblocker skript to pull adlists for Unbound

### Some steps

1. **Initial Setup:** Start by configuring the OpenBSD gateway with the provided PF configuration to set up initial firewall rules.
2. **Dynamic IP Script:** Implement the dynamic IP update script to maintain an up-to-date whitelist of IPs that can access the VPN.
3. **Cron Configuration:** Schedule the provided cron jobs to automate the updating and maintenance tasks.
4. **DNS Encryption:** Follow the DNS setup instructions to encrypt DNS queries, using either DoH or ODoH.
5. **Ad Blocking:** Set up the ad blocker script to filter out unwanted ads.

### Detailed Configuration Scripts and Commands

- **Dynamic IP Update Script (`getpara.sh`)**: This script resolves the current IP address for a specified FQDN and updates the PF table with any changes.
  
- **PF Configuration (`pf.conf`)**: Includes rules for blocking, allowing SSH from specific IPs, handling Wireguard traffic, and default deny policies.

- **Cron Jobs**: Automates system updates, VPN renewals, and the dynamic IP update script.

- **DNS Configuration**: Setup guides for DoH and ODoH, including configuration changes for `dnscrypt-proxy`.

- **Ad Blocker Script**: Instructions and script for setting up ad blocking on OpenBSD using Unbound.

#### Some OpenBSD Cronjobs right away
-  add via `crontab -e`  
```
@reboot /bin/sleep 30 && /usr/local/bin/wg-quick up wg0
@reboot /bin/sleep 30 && /usr/sbin/rcctl restart unbound
30 13 * * * /usr/sbin/syspatch -c 
32 13 * * * /usr/sbin/syspatch
35 13 * * * /usr/sbin/pkg_add -u

30 4 * * 3 /usr/local/getpara.sh
0 0 * * * /usr/local/getpara.sh
2 0 * * * /usr/sbin/rcctl restart unbound
```
### Firewall: OpenBSD PF rules for static & dynamic ips

- You edit the pf rules on ` /etc/pf.conf ` and check via  `pfctl -nf /etc/pf.conf` and  load them via  `pfctl -f  /etc/pf.conf`

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

### Skript to add the dynamic hosts
- Important: All your clients will need to get FQDNs, and you can do that by adding for example containers in your home, work etc, that use tools like `ddclient` + any DYNDNS-hoster.
- Next, *Ensure you replace `myhost.myhoster.org` with your actual domain domain.*
- The script below will access the FQDN and add it to the firewall ruletable for access.

I've deployed the following script on `/usr/local/getpara.sh` it creates `temp_gotten_para` as well as `gotten-para` which contains the dynamic IPs to be added to the firewall for access.

```sh
#!/bin/sh

# FQDN to resolve
FQDN="myhost.myhoster.org"

# Variables
TEMP_IP_FILE="/usr/local/temp_gotten_para"
FINAL_IP_FILE="/usr/local/gotten-para"
MAX_IP_COUNT=3
IP_RETENTION_DAYS=10

# Resolve the current IP address of the FQDN
CURRENT_IP=$(dig +short $FQDN)
CURRENT_TIMESTAMP=$(date +%s)

# Ensure FINAL_IP_FILE exists
if [ ! -f "$FINAL_IP_FILE" ]; then
    touch "$FINAL_IP_FILE"
fi

# Exit if no IP is resolved
[ -z "$CURRENT_IP" ] && echo "No IP address found for $FQDN" && exit 1

# Append current IP with timestamp to TEMP_IP_FILE for processing
echo "$CURRENT_TIMESTAMP $CURRENT_IP" >> "$TEMP_IP_FILE"

# Process TEMP_IP_FILE to ensure uniqueness, limit the number of IPs, and consider the retention period
awk -v max_count=$MAX_IP_COUNT -v retention_days=$IP_RETENTION_DAYS -v current_time=$CURRENT_TIMESTAMP '{
    ip = $2
    timestamp = $1
    if (!seen[ip]++ && (current_time - timestamp) <= (retention_days * 86400)) {
        print ip
        if (++count >= max_count) exit
    }
}' "$TEMP_IP_FILE" | sort -u | tail -n $MAX_IP_COUNT > "$FINAL_IP_FILE"

# Reload the PF table with the updated IP list
pfctl -t dynamic_hosts -T replace -f "$FINAL_IP_FILE" && echo "pf table reloaded with updated IP list."

```
### Wireguards

- After you installed the package via `pkg_add wireguard-tools`,your gateways `wg0.conf` looks like this on `\etc\wireguard\wg0.conf`and you can trigger restarts for the interface like `wg-quick down wg0 && sleep 5 && wg-quick up wg0`.
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
- For this just follow the guide from SwaroopGiri: (https://github.com/SwaroopGiri/Pihole-with-Anonymized-ODOH)
- We need to work with dnscrypt for this, and set it to be running on 127.0.0.1@54, which unbound will just forward requests to (and itself be listening on 53, only allowing getting access from Wireguard clients):

- Here is how you add the dnscrypt proxy package and check paths, plus how to do restarts and enabling of it
```
pkg_add dnscrypt-proxy
pkg_info -L dnscrypt-proxy
...
rcctl enable dnscrypt_proxy
rcctl restart unbound
rcctl restart dnscrypt_proxy
```
  - Important settings:
```
server_names = ['odoh-cloudflare']
odoh_servers = true
require_dnssec = true   
require_nofilter = false
cache = false   #we will use the Pi-Hole cache
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

# FQDN to resolve
FQDN="myhost.duckdns.org"

# Variables
TEMP_IP_FILE="/usr/local/temp_gotten_para"
FINAL_IP_FILE="/usr/local/gotten-para"
MAX_IP_COUNT=3
IP_RETENTION_DAYS=10
IP_SET_NAME="dynamic_hosts"
WG_ZONE="wireguard0"
WG_PORT="51820" # Ensure this is set to the correct WireGuard port

# Resolve the current IP address of the FQDN
CURRENT_IP=$(dig +short $FQDN)
CURRENT_TIMESTAMP=$(date +%s)

# Ensure FINAL_IP_FILE exists
if [ ! -f "$FINAL_IP_FILE" ]; then
    touch "$FINAL_IP_FILE"
fi

# Exit if no IP is resolved
[ -z "$CURRENT_IP" ] && echo "No IP address found for $FQDN" && exit 1

# Append current IP with timestamp to TEMP_IP_FILE for processing
echo "$CURRENT_TIMESTAMP $CURRENT_IP" >> "$TEMP_IP_FILE"

# Process TEMP_IP_FILE to ensure uniqueness, limit the number of IPs, and consider the retention period
awk -v max_count=$MAX_IP_COUNT -v retention_days=$IP_RETENTION_DAYS -v current_time=$CURRENT_TIMESTAMP '{
    ip = $2
    timestamp = $1
    if (!seen[ip]++ && (current_time - timestamp) <= (retention_days * 86400)) {
        print ip
        if (++count >= max_count) exit
    }
}' "$TEMP_IP_FILE" | sort -u | tail -n $MAX_IP_COUNT > "$FINAL_IP_FILE"

# Check if the IP set exists and delete it if it does
if firewall-cmd --permanent --get-ipsets | grep -qw "$IP_SET_NAME"; then
    firewall-cmd --permanent --delete-ipset=$IP_SET_NAME
fi

# Create the IP set anew and populate it with the latest IPs
firewall-cmd --permanent --new-ipset=$IP_SET_NAME --type=hash:ip
while read -r ip; do
  firewall-cmd --permanent --ipset=$IP_SET_NAME --add-entry="$ip"
done < "$FINAL_IP_FILE"
firewall-cmd --reload

echo "Firewalld IP set updated with latest IPs."
```
- We additionally add the dynamic hosts via `/usr/local/updatepara.sh`

```
# Define the WireGuard zone and port variables
WG_ZONE="public"
WG_PORT="51820"

# Add the rich rule with expanded variables
sudo firewall-cmd --permanent --zone=$WG_ZONE --add-rich-rule="rule family=\"ipv4\" source ipset=\"dynamic_hosts\" port port=\"$WG_PORT\" protocol=\"udp\" accept"
sudo firewall-cmd --reload

echo "Rich rule added to $WG_ZONE zone for WireGuard access on port $WG_PORT."
```
- In case we wanna confirm para entries:
```
firewall-cmd --ipset=dynamic_hosts --get-entries
```
- In case we wanna remove entries:
```
firewall-cmd --ipset=dynamic_hosts --get-entries | xargs -I{} firewall-cmd --permanent --ipset=dynamic_hosts --remove-entry={} && firewall-cmd --reload
```
- We need to also add this to the cronjob of the Linux server, for example daily:
```
0 0 * * * /usr/local/getpara.sh
0 0 * * * /usr/local/updatepara.sh
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

Thanks for the read, I hope you find it useful in any way. 
If you have ideas to get this more secure / paranoid in any way, then I'm happy to listen!
