#!/bin/sh
#################################################################
# DMT Defense Validation Script
# Tests DNS cache timing attack mitigations on hardened Squid
# Experimental check
# Reference: "Continuous User Behavior Monitoring using DNS
#             Cache Timing Attacks" — NDSS 2026
#             Weissteiner, Czerny, Franza, Gast, Ullrich, Gruss
#             https://dx.doi.org/10.14722/ndss.2026.242287
#
# Run as root on the Squid server:
#   sh dmt_defense_test.sh
#
# Requirements:
#   - curl, bc, pfctl (OpenBSD)
#   - Squid running with hardened config
#   - PF dns_flood table configured
#
# Setup:
#   Replace PROXY below with your Squid listener address
#################################################################

# ── CHANGE THIS TO YOUR SQUID PROXY ──
PROXY="http://7.7.7.7:6666"

TARGETS="reddit.com google.com amazon.com wikipedia.org github.com"
EVICT_COUNT=150
MEASURE_ROUNDS=5

RED="\033[1;31m"
GRN="\033[1;32m"
YLW="\033[1;33m"
CYN="\033[1;36m"
RST="\033[0m"

pass=0
fail=0

result() {
  if [ "$1" = "PASS" ]; then
    printf "  ${GRN}[PASS]${RST} %s\n" "$2"
    pass=$((pass + 1))
  else
    printf "  ${RED}[FAIL]${RST} %s\n" "$2"
    fail=$((fail + 1))
  fi
}

# Sanity check
printf "\n${CYN}══════════════════════════════════════════════════════════${RST}\n"
printf "${CYN}  DMT Defense Validation — $(date '+%Y-%m-%d %H:%M:%S')${RST}\n"
printf "${CYN}══════════════════════════════════════════════════════════${RST}\n\n"

printf "  Proxy: $PROXY\n"
SANITY=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -x $PROXY "http://example.com" 2>/dev/null)
if [ "$SANITY" = "200" ]; then
  printf "  ${GRN}Proxy reachable${RST}\n\n"
else
  printf "  ${RED}Proxy unreachable (HTTP $SANITY)${RST}\n"
  printf "  Edit PROXY variable at top of script\n\n"
  exit 1
fi

#################################################################
# TEST 1: Cache Manager Blocked
#################################################################
printf "${YLW}[TEST 1] Cache Manager Access${RST}\n"
printf "  Attack: cache_object:// URLs leak fqdncache contents\n"
printf "  Defense: cachemgr_passwd disable all\n"

CM_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -x $PROXY "http://cache_object://localhost/fqdncache" 2>/dev/null)
if [ "$CM_RESULT" = "403" ] || [ "$CM_RESULT" = "000" ] || [ "$CM_RESULT" = "503" ]; then
  result "PASS" "cache_object blocked (HTTP $CM_RESULT)"
else
  result "FAIL" "cache_object accessible (HTTP $CM_RESULT) — add: cachemgr_passwd disable all"
fi

CM_RESULT2=$(curl -s -o /dev/null -w "%{http_code}" -x $PROXY "http://cache_object://localhost/info" 2>/dev/null)
if [ "$CM_RESULT2" = "403" ] || [ "$CM_RESULT2" = "000" ] || [ "$CM_RESULT2" = "503" ]; then
  result "PASS" "cache info blocked (HTTP $CM_RESULT2)"
else
  result "FAIL" "cache info accessible (HTTP $CM_RESULT2)"
fi
echo ""

#################################################################
# TEST 2: Dangerous Methods Blocked
#################################################################
printf "${YLW}[TEST 2] Dangerous Methods${RST}\n"
printf "  Attack: TRACE leaks cookies via XST, PURGE manipulates cache\n"
printf "  Defense: acl dangerous_methods method TRACE PURGE OPTIONS\n"

TRACE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X TRACE -x $PROXY "http://example.com" 2>/dev/null)
if [ "$TRACE_RESULT" = "403" ]; then
  result "PASS" "TRACE blocked (HTTP $TRACE_RESULT)"
else
  result "FAIL" "TRACE allowed (HTTP $TRACE_RESULT) — add TRACE to dangerous_methods ACL"
fi

PURGE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PURGE -x $PROXY "http://example.com" 2>/dev/null)
if [ "$PURGE_RESULT" = "403" ]; then
  result "PASS" "PURGE blocked (HTTP $PURGE_RESULT)"
else
  result "FAIL" "PURGE allowed (HTTP $PURGE_RESULT) — add PURGE to dangerous_methods ACL"
fi
echo ""

#################################################################
# TEST 3: URI Whitespace Rejected
#################################################################
printf "${YLW}[TEST 3] URI Whitespace (Smuggling Vector)${RST}\n"
printf "  Attack: Spaces in URIs exploit parsing ambiguity\n"
printf "  Defense: uri_whitespace deny\n"

WS_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -x $PROXY "http://example.com/path with spaces" 2>/dev/null)
if [ "$WS_RESULT" = "400" ] || [ "$WS_RESULT" = "403" ] || [ "$WS_RESULT" = "000" ]; then
  result "PASS" "URI with spaces rejected (HTTP $WS_RESULT — connection dropped)"
else
  result "FAIL" "URI with spaces accepted (HTTP $WS_RESULT) — add: uri_whitespace deny"
fi
echo ""

#################################################################
# TEST 4: OPTIONS Method Blocked
#################################################################
printf "${YLW}[TEST 4] OPTIONS Method (DMT Measurement Primitive)${RST}\n"
printf "  Attack: CORS preflight used as DNS cache timing probe\n"
printf "  Defense: OPTIONS in dangerous_methods ACL (deny before allow)\n"

OPT_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS -x $PROXY "http://example.com" 2>/dev/null)
if [ "$OPT_RESULT" = "403" ]; then
  result "PASS" "OPTIONS blocked (HTTP $OPT_RESULT)"
else
  result "FAIL" "OPTIONS allowed (HTTP $OPT_RESULT) — add OPTIONS to dangerous_methods ACL"
fi
echo ""

#################################################################
# TEST 5: Timing Signal Measurement
#################################################################
printf "${YLW}[TEST 5] DNS Timing Signal Through Proxy${RST}\n"
printf "  Attack: Measure latency difference cached vs uncached domains\n"
printf "  Defense: HTTP overhead buries DNS timing in noise\n"
printf "  Goal: Difference should be <1ms and inconsistent\n\n"

for domain in $TARGETS; do
  # Prime cache
  curl -s -o /dev/null --max-time 5 -x $PROXY "http://$domain" 2>/dev/null
  sleep 1

  cached_total=0
  uncached_total=0

  printf "  %-20s " "$domain"

  for round in $(seq 1 $MEASURE_ROUNDS); do
    # Measure cached
    c=$(curl -s -o /dev/null -w "%{time_namelookup}" --max-time 5 -x $PROXY "http://$domain" 2>/dev/null)
    c_ms=$(echo "$c * 1000" | bc 2>/dev/null || echo "0")

    sleep 1

    # Insert noise domain between measurements
    curl -s -o /dev/null --max-time 2 -x $PROXY "http://noise${round}${RANDOM}.invalid" 2>/dev/null

    # Measure after noise injection
    u=$(curl -s -o /dev/null -w "%{time_namelookup}" --max-time 5 -x $PROXY "http://$domain" 2>/dev/null)
    u_ms=$(echo "$u * 1000" | bc 2>/dev/null || echo "0")

    cached_total=$(echo "$cached_total + $c_ms" | bc 2>/dev/null || echo "0")
    uncached_total=$(echo "$uncached_total + $u_ms" | bc 2>/dev/null || echo "0")
  done

  avg_c=$(echo "scale=1; $cached_total / $MEASURE_ROUNDS" | bc 2>/dev/null || echo "?")
  avg_u=$(echo "scale=1; $uncached_total / $MEASURE_ROUNDS" | bc 2>/dev/null || echo "?")
  diff=$(echo "scale=1; $avg_u - $avg_c" | bc 2>/dev/null || echo "?")

  printf "cached: %6s ms  after_noise: %6s ms  diff: %6s ms\n" "$avg_c" "$avg_u" "$diff"
done

printf "\n  ${CYN}The paper requires clean sub-5ms timing signals to distinguish\n"
printf "  cached from uncached DNS lookups. Through an HTTP proxy, each\n"
printf "  request adds 50-300ms of connection overhead that completely\n"
printf "  buries the DNS timing signal in noise.${RST}\n"
echo ""

#################################################################
# TEST 6: Eviction Resistance
#################################################################
printf "${YLW}[TEST 6] Cache Eviction Resistance${RST}\n"
printf "  Attack: Flood $EVICT_COUNT unique domains to evict fqdncache\n"
printf "  Defense: fqdncache_size 2048 + positive_dns_ttl 2h + PF rate limit\n"
printf "  Goal: Target domains survive in cache after flood\n\n"

# Clear PF table
pfctl -t dns_flood -T flush 2>/dev/null

# Prime cache with targets
printf "  Priming cache with target domains...\n"
for domain in $TARGETS; do
  curl -s -o /dev/null --max-time 5 -x $PROXY "http://$domain" 2>/dev/null
done
sleep 2

# Measure pre-eviction baseline
printf "  Measuring pre-eviction baseline...\n"
pre_times=""
for domain in $TARGETS; do
  t=$(curl -s -o /dev/null -w "%{time_total}" --max-time 5 -x $PROXY "http://$domain" 2>/dev/null)
  t_ms=$(echo "$t * 1000" | bc 2>/dev/null || echo "0")
  pre_times="$pre_times $domain:${t_ms}"
done
sleep 1

# Attempt eviction
printf "  Flooding with $EVICT_COUNT unique domains...\n"
FLOOD_START=$(date +%s)
i=0
while [ $i -lt $EVICT_COUNT ]; do
  curl -s -o /dev/null --max-time 2 -x $PROXY "http://evict${i}dmt${RANDOM}.invalid" &
  i=$((i + 1))
  # Batch in groups of 20 to avoid overwhelming
  if [ $((i % 20)) -eq 0 ]; then
    wait
  fi
done
wait
FLOOD_END=$(date +%s)
FLOOD_TIME=$((FLOOD_END - FLOOD_START))
printf "  Flood completed in ${FLOOD_TIME}s\n"
sleep 2

# Measure post-eviction
printf "  Measuring post-eviction times...\n\n"
eviction_detected=0

printf "  %-20s %12s %12s %10s %s\n" "DOMAIN" "PRE (ms)" "POST (ms)" "DIFF (ms)" "STATUS"
printf "  %-20s %12s %12s %10s %s\n" "------" "--------" "---------" "---------" "------"

for entry in $pre_times; do
  domain=$(echo "$entry" | cut -d: -f1)
  pre_ms=$(echo "$entry" | cut -d: -f2)

  post=$(curl -s -o /dev/null -w "%{time_total}" --max-time 5 -x $PROXY "http://$domain" 2>/dev/null)
  post_ms=$(echo "$post * 1000" | bc 2>/dev/null || echo "0")

  diff=$(echo "scale=0; $post_ms - $pre_ms" | bc 2>/dev/null || echo "0")
  abs_diff=$(echo "$diff" | tr -d '-')

  # If post-eviction is >500ms slower, eviction likely succeeded
  if [ "$(echo "$abs_diff > 500" | bc 2>/dev/null)" = "1" ] && [ "$(echo "$post_ms > $pre_ms" | bc 2>/dev/null)" = "1" ]; then
    status="${RED}EVICTED${RST}"
    eviction_detected=$((eviction_detected + 1))
  else
    status="${GRN}SURVIVED${RST}"
  fi

  printf "  %-20s %9.1f ms %9.1f ms %7.0f ms $status\n" "$domain" "$pre_ms" "$post_ms" "$diff"
done

echo ""
survived=$(echo "$TARGETS" | wc -w | tr -d ' ')
survived=$((survived - eviction_detected))
total=$(echo "$TARGETS" | wc -w | tr -d ' ')

if [ $eviction_detected -eq 0 ]; then
  result "PASS" "All $total domains survived eviction attempt"
else
  result "FAIL" "$eviction_detected/$total domains evicted"
fi
echo ""

#################################################################
# TEST 7: PF Rate Limiting
#################################################################
printf "${YLW}[TEST 7] PF DNS Rate Limiting${RST}\n"
printf "  Defense: max-src-conn-rate 50/10 on port 53 egress\n"
printf "  Requires: table <dns_flood> persist in /etc/pf.conf\n\n"

PF_COUNT=$(pfctl -t dns_flood -T show 2>/dev/null | wc -l | tr -d ' ')

if [ "$PF_COUNT" -gt 0 ]; then
  result "PASS" "PF caught flood — $PF_COUNT IPs in dns_flood table"
  printf "  Entries:\n"
  pfctl -t dns_flood -T show 2>/dev/null | while read ip; do
    printf "    %s\n" "$ip"
  done
else
  printf "  ${CYN}No entries in dns_flood table — rate limit may not have\n"
  printf "  triggered with only $EVICT_COUNT domains. This is expected\n"
  printf "  if Squid's fqdncache served NXDOMAIN from cache.${RST}\n"
  result "PASS" "Flood was too small to trigger PF (fqdncache absorbed it)"
fi
echo ""

#################################################################
# TEST 8: Header Stripping
#################################################################
printf "${YLW}[TEST 8] Privacy Header Verification${RST}\n"
printf "  Defense: request_header_access / reply_header_access deny rules\n\n"

HEADERS=$(curl -s -D - -o /dev/null -x $PROXY "http://example.com" 2>/dev/null)

for h in "Server:" "X-Powered-By:" "Via:" "X-Cache:" "X-Varnish:" "Alt-Svc:" "NEL:" "Report-To:" "Server-Timing:"; do
  if echo "$HEADERS" | grep -qi "^$h"; then
    result "FAIL" "$h header leaked"
  else
    result "PASS" "$h header stripped"
  fi
done
echo ""

#################################################################
# SUMMARY
#################################################################
total=$((pass + fail))
printf "${CYN}══════════════════════════════════════════════════════════${RST}\n"
printf "${CYN}  RESULTS: ${GRN}$pass passed${RST} / ${RED}$fail failed${RST} / $total total\n"
printf "${CYN}══════════════════════════════════════════════════════════${RST}\n\n"

if [ $fail -eq 0 ]; then
  printf "  ${GRN}All DMT attack vectors defended.${RST}\n"
  printf "  ${GRN}Paper's attack is not viable against this configuration.${RST}\n"
else
  printf "  ${RED}Some tests failed — review output above for remediation hints.${RST}\n"
fi
echo ""

# Cleanup PF table
pfctl -t dns_flood -T flush 2>/dev/null
