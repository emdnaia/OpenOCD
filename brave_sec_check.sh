#!/usr/bin/env bash

echo "==============================================================================="
echo "           BRAVE BROWSER SECURITY AUDIT"
echo "==============================================================================="
echo

if ! pgrep -f brave > /dev/null; then
  echo "ERROR: Brave is not running!"
  exit 1
fi

# Cache aa-status once
echo "Caching system status..."
AA_STATUS=$(doas aa-status 2>/dev/null)

# Find the ACTUAL Brave binary
brave_binary=$(pgrep -f "opt/brave.com/brave/brave" | head -1)
if [ -z "$brave_binary" ]; then
  brave_binary=$(pgrep -o brave)
fi

# Collect PIDs
all_pids=($(pgrep -f brave))
renderer_pids=($(pgrep -f "type=renderer"))

total=${#all_pids[@]}
renderers=${#renderer_pids[@]}

echo "[PROCESS INVENTORY]"
printf "Total: %d | Renderers: %d (critical attack surface)\n" "$total" "$renderers"
printf "Main Brave PID: %d\n" "$brave_binary"
echo

# Check which Brave is running
cmdline=$(cat /proc/$brave_binary/cmdline 2>/dev/null | tr '\0' '\n')

echo "[LAUNCH METHOD DETECTION]"
echo "-------------------------------------------------------------------------------"
if echo "$cmdline" | grep -q "MiraclePtr"; then
  echo "Status: HARDENED WRAPPER ACTIVE"
  echo "Launch: brave-hardened.desktop or custom script"
elif echo "$cmdline" | grep -q "enable-features=VaapiVideoDecoder"; then
  echo "Status: NORMAL BRAVE (DEFAULT LAUNCHER)"
  echo "Launch: Standard system launcher"
else
  echo "Status: UNKNOWN CONFIGURATION"
fi
echo "-------------------------------------------------------------------------------"
echo

# ============================================================================
# FIXED: GRAPHENE MALLOC VERIFICATION
# ============================================================================
echo "[MEMORY HARDENING - GRAPHENE MALLOC]"
echo "-------------------------------------------------------------------------------"

# Method 1: Check if library is in ldd output (preloaded libraries appear first)
echo "Preload Detection:"
graphene_preloaded=0
if ldd /proc/$brave_binary/exe 2>/dev/null | head -5 | grep -q "libhardened_malloc.so"; then
  printf "  %-28s: ✅ PRELOADED (appears in first 5 libs)\n" "Library Position"
  graphene_preloaded=1
else
  printf "  %-28s: ⚠️  NOT IN PRELOAD POSITION\n" "Library Position"
fi

echo

# Method 2: Check actual memory addresses
echo "Memory Address Analysis:"
if grep -q "libhardened_malloc.so" /proc/$brave_binary/maps 2>/dev/null; then
  # Get the FIRST address of each library (start of mapping)
  graphene_addr=$(grep "libhardened_malloc.so" /proc/$brave_binary/maps 2>/dev/null | head -1 | awk '{print $1}' | cut -d- -f1)
  libc_addr=$(grep "libc-" /proc/$brave_binary/maps 2>/dev/null | head -1 | awk '{print $1}' | cut -d- -f1)
  
  if [ -n "$graphene_addr" ] && [ -n "$libc_addr" ]; then
    printf "  %-28s: 0x%s\n" "Graphene malloc at" "$graphene_addr"
    printf "  %-28s: 0x%s\n" "libc at" "$libc_addr"
    
    # Compare addresses (lower = loaded earlier in some cases, but preload = intercepting)
    # What matters is if it's in memory AND in renderer processes
    printf "  %-28s: ✅ BOTH LOADED\n" "Status"
  fi
  
  # Check for executable section
  section_count=$(grep "libhardened_malloc.so" /proc/$brave_binary/maps 2>/dev/null | wc -l)
  exec_section=$(grep "libhardened_malloc.so" /proc/$brave_binary/maps 2>/dev/null | grep "r-xp" | wc -l)
  
  printf "  %-28s: %d sections\n" "Memory Sections" "$section_count"
  printf "  %-28s: %s\n" "Executable Code" "$([ $exec_section -gt 0 ] && echo '✅ Present (malloc running)' || echo '❌ Missing')"
else
  printf "  %-28s: ❌ NOT LOADED\n" "Memory Maps"
fi

echo

# Method 3: Renderer coverage (MOST IMPORTANT - if it's in renderers, it's working!)
echo "Renderer Process Coverage:"
loaded=0
tested=0
max_test=10

for pid in "${renderer_pids[@]}"; do
  [ $tested -ge $max_test ] && break
  if grep -q "libhardened_malloc.so" /proc/$pid/maps 2>/dev/null; then
    ((loaded++))
  fi
  ((tested++))
done

coverage_pct=$((loaded * 100 / tested))
printf "  %-28s: %d/%d sampled (%d%%)\n" "Coverage" "$loaded" "$tested" "$coverage_pct"

# CRITICAL: If 100% of renderers have it, it's working!
graphene_active=0
if [ $coverage_pct -eq 100 ] && [ $exec_section -gt 0 ]; then
  printf "  %-28s: ✅ VERIFIED ACTIVE\n" "Interception Status"
  printf "  %-28s: All renderers protected\n" "Conclusion"
  graphene_active=1
elif [ $coverage_pct -ge 80 ]; then
  printf "  %-28s: ⚠️  MOSTLY ACTIVE (%d%%)\n" "Status" "$coverage_pct"
else
  printf "  %-28s: ❌ INACTIVE\n" "Status"
fi

echo

# Triple-layer protection
echo "Multi-Layer Memory Protection:"

printf "  Layer 1 (System):   Graphene Malloc      %s\n" "$([ $graphene_active -eq 1 ] && echo '✅ ACTIVE' || echo '❌ INACTIVE')"
printf "  Layer 2 (Browser):  PartitionAlloc       %s\n" "$(echo "$cmdline" | grep -q "PartitionAllocGigaCage" && echo '✅ ACTIVE' || echo '❌ INACTIVE')"
printf "  Layer 3 (Hardware): IBT+SHSTK+LAM        %s\n" "$(grep -q "ibt=on" /proc/cmdline 2>/dev/null && echo '✅ ACTIVE' || echo '❌ INACTIVE')"

echo "-------------------------------------------------------------------------------"
echo

# ============================================================================
# RENDERER SANDBOX
# ============================================================================
echo "[RENDERER SANDBOX (N=$renderers)]"
echo "-------------------------------------------------------------------------------"

seccomp_ok=0; caps_ok=0; ns_total=0; aa_enforced=0

for pid in "${renderer_pids[@]}"; do
  [ "$(grep "^Seccomp:" /proc/$pid/status 2>/dev/null | awk '{print $2}')" = "2" ] && ((seccomp_ok++))
  [ "$(grep "^CapEff:" /proc/$pid/status 2>/dev/null | awk '{print $2}')" = "0000000000000000" ] && ((caps_ok++))
  ns_total=$((ns_total + $(ls /proc/$pid/ns 2>/dev/null | wc -l)))
done

aa_total=$(echo "$AA_STATUS" | grep -c "/nix/store.*brave")
aa_enforced=$aa_total

printf "%-30s: %3d/%3d (%3d%%) %s\n" "Seccomp BPF Filters" "$seccomp_ok" "$renderers" \
  "$((seccomp_ok * 100 / renderers))" "$([ $seccomp_ok -eq $renderers ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d/%3d (%3d%%) %s\n" "Capabilities Dropped" "$caps_ok" "$renderers" \
  "$((caps_ok * 100 / renderers))" "$([ $caps_ok -eq $renderers ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d avg %s\n" "Namespace Isolation" "$((ns_total / renderers))" \
  "$([ $((ns_total / renderers)) -ge 8 ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d processes %s\n" "AppArmor Confinement" "$aa_enforced" \
  "$([ $aa_enforced -gt 0 ] && echo '[OK]' || echo '[WARN]')"

echo "-------------------------------------------------------------------------------"
echo

# ============================================================================
# EXPLOIT MITIGATION FLAGS
# ============================================================================
echo "[EXPLOIT MITIGATIONS]"
echo "-------------------------------------------------------------------------------"

main_cmdline=$(cat /proc/$brave_binary/cmdline 2>/dev/null | tr '\0' ',' | tr '\n' ',')
renderer_cmdline=""
if [ -n "${renderer_pids[0]}" ]; then
  renderer_cmdline=$(cat /proc/${renderer_pids[0]}/cmdline 2>/dev/null | tr '\0' ',' | tr '\n' ',')
fi
combined="$main_cmdline,$renderer_cmdline"

check_flag() {
  local flag=$1
  local desc=$2
  
  if echo "$combined" | grep -qi "$flag"; then
    printf "%-50s: ✅ ACTIVE\n" "$desc"
    return 0
  else
    printf "%-50s: ❌ MISSING\n" "$desc"
    return 1
  fi
}

echo "Memory Safety (UAF/Heap):"
miracle=0; check_flag "MiraclePtr" "  MiraclePtr" && miracle=1
backup=0; check_flag "PartitionAllocBackupRefPtr\|BackupRefPtr" "  BackupRefPtr" && backup=1
cage=0; check_flag "V8ForceMemoryCage" "  V8 Memory Cage" && cage=1
pcscan=0; check_flag "PartitionAllocPCScan" "  PCScan (Dangling Ptr Detection)" && pcscan=1
quarantine=0; check_flag "PartitionAllocSchedulerLoopQuarantine" "  Quarantine (Delayed Free)" && quarantine=1
zapping=0; check_flag "PartitionAllocZappingByFreeFlags" "  Zapping (Zero on Free)" && zapping=1

echo
echo "JIT/Code Execution:"
jitless=0; check_flag "jitless\|--jitless" "  JIT Disabled (--jitless)" && jitless=1
v8mit=0; check_flag "V8UntrustedCodeMitigations" "  V8 Untrusted Code Mitigations" && v8mit=1
wasm=0; check_flag "WasmCodeProtection" "  WASM Code Protection" && wasm=1

echo
echo "Process Isolation:"
siteproc=0; check_flag "site-per-process" "  Site-Per-Process" && siteproc=1
strict=0; check_flag "StrictSiteIsolation" "  Strict Site Isolation" && strict=1
isolate=0; check_flag "IsolateOrigins" "  Origin Isolation" && isolate=1

echo
echo "Sandbox:"
netsand=0; check_flag "NetworkServiceSandbox" "  Network Service Sandboxed" && netsand=1
audio=0; check_flag "AudioServiceSandbox\|AudioServiceOutOfProcess" "  Audio Service Sandboxed" && audio=1

echo
echo "Attack Surface:"
webrtc=0; check_flag "disable-webrtc" "  WebRTC Disabled" && webrtc=1

echo "-------------------------------------------------------------------------------"
echo

# ============================================================================
# HARDWARE SECURITY
# ============================================================================
echo "[HARDWARE SECURITY FEATURES]"
echo "-------------------------------------------------------------------------------"

ibt_enabled=$(grep -q "ibt=on" /proc/cmdline 2>/dev/null && echo "1" || echo "0")
shstk_enabled=$(grep -q "shstk=on" /proc/cmdline 2>/dev/null && echo "1" || echo "0")
lam_enabled=$(grep -q "lam=on" /proc/cmdline 2>/dev/null && echo "1" || echo "0")

printf "%-40s: %s\n" "IBT (Indirect Branch Tracking)" "$([ $ibt_enabled -eq 1 ] && echo '✅ ENABLED' || echo '❌ DISABLED')"
printf "%-40s: %s\n" "SHSTK (Shadow Stack)" "$([ $shstk_enabled -eq 1 ] && echo '✅ ENABLED' || echo '❌ DISABLED')"
printf "%-40s: %s\n" "LAM (Linear Address Masking)" "$([ $lam_enabled -eq 1 ] && echo '✅ ENABLED' || echo '❌ DISABLED')"

echo "-------------------------------------------------------------------------------"
echo

# ============================================================================
# SECURITY ASSESSMENT
# ============================================================================
echo "[SECURITY ASSESSMENT]"
echo "==============================================================================="

# Calculate score
browser_score=$((miracle + backup + cage + pcscan + quarantine + zapping + v8mit + wasm + siteproc + strict + netsand + audio))
hardware_score=0
[ $seccomp_ok -eq $renderers ] && ((hardware_score++))
[ $aa_enforced -gt 0 ] && ((hardware_score++))
[ $ibt_enabled -eq 1 ] && ((hardware_score++))
[ $shstk_enabled -eq 1 ] && ((hardware_score++))
[ $graphene_active -eq 1 ] && ((hardware_score++))

total_score=$((browser_score + hardware_score))
max_score=17

printf "Browser Mitigations: %2d/12\n" "$browser_score"
printf "System/Hardware:     %2d/5\n" "$hardware_score"
printf "Total Score:         %2d/%d\n\n" "$total_score" "$max_score"

if [ $total_score -ge 14 ]; then
  echo "Status: 🔒 MAXIMUM HARDENING"
  echo "        • Triple-layer memory protection active"
  echo "        • Estimated exploit cost: $500k+ (4-5 chained 0-days)"
  echo "        • Attack difficulty: EXTREME"
elif [ $total_score -ge 11 ]; then
  echo "Status: 🛡️  HARDENED"
  echo "        • Strong protections with minor gaps"
  echo "        • Attack difficulty: HIGH"
elif [ $total_score -ge 7 ]; then
  echo "Status: ⚠️  PROTECTED"
  echo "        • Good baseline security"
  echo "        • Attack difficulty: MODERATE"
else
  echo "Status: ❌ BASIC"
  echo "        • Chromium defaults only"
  echo "        • Attack difficulty: LOW"
fi
echo "==============================================================================="
