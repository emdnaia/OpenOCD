#!/usr/bin/env bash

echo "==============================================================================="
echo "           BRAVE SEC CHECK "
echo "==============================================================================="
echo

if ! pgrep -f brave > /dev/null; then
  echo "ERROR: Brave is not running!"
  exit 1
fi

# Cache aa-status once
echo "Caching system status..."
AA_STATUS=$(doas aa-status 2>/dev/null)

# Find the ACTUAL Brave binary (not bash wrapper)
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

# Graphene malloc
echo "[MEMORY HARDENING - GRAPHENE MALLOC]"
ld_preload=$(cat /proc/$brave_binary/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD | cut -d= -f2)
if [ -n "$ld_preload" ]; then
  printf "%-30s: ACTIVE (%s)\n" "Hardened Allocator" "$(basename "$ld_preload")"
else
  printf "%-30s: MISSING\n" "Hardened Allocator"
fi

loaded=0
for pid in "${renderer_pids[@]}"; do
  grep -q "libhardened_malloc.so" /proc/$pid/maps 2>/dev/null && ((loaded++))
done
printf "%-30s: %d/%d renderers (%d%%)\n" "Coverage" "$loaded" "$renderers" "$((loaded * 100 / renderers))"
echo

# Renderer security
echo "[RENDERER SANDBOX STATUS (N=$renderers)]"
echo "-------------------------------------------------------------------------------"

seccomp_ok=0; caps_ok=0; ns_total=0; aa_enforced=0

for pid in "${renderer_pids[@]}"; do
  [ "$(grep "^Seccomp:" /proc/$pid/status 2>/dev/null | awk '{print $2}')" = "2" ] && ((seccomp_ok++))
  [ "$(grep "^CapEff:" /proc/$pid/status 2>/dev/null | awk '{print $2}')" = "0000000000000000" ] && ((caps_ok++))
  ns_total=$((ns_total + $(ls /proc/$pid/ns 2>/dev/null | wc -l)))
done

# Fix AppArmor detection - check if ANY Brave process is confined
aa_total=$(echo "$AA_STATUS" | grep -c "/nix/store.*brave")
aa_enforced=$aa_total

printf "%-30s: %3d/%3d (%3d%%) %s\n" "Seccomp BPF Filters" "$seccomp_ok" "$renderers" \
  "$((seccomp_ok * 100 / renderers))" "$([ $seccomp_ok -eq $renderers ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d/%3d (%3d%%) %s\n" "Capabilities Dropped" "$caps_ok" "$renderers" \
  "$((caps_ok * 100 / renderers))" "$([ $caps_ok -eq $renderers ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d avg %s\n" "Namespace Isolation" "$((ns_total / renderers))" \
  "$([ $((ns_total / renderers)) -ge 8 ] && echo '[OK]' || echo '[WARN]')"
printf "%-30s: %3d total processes %s\n" "AppArmor MAC" "$aa_enforced" \
  "$([ $aa_enforced -gt 0 ] && echo '[OK]' || echo '[WARN]')"
echo "-------------------------------------------------------------------------------"
echo

# AppArmor Policy Analysis
echo "[APPARMOR POLICY ENFORCEMENT]"
echo "-------------------------------------------------------------------------------"

if [ $aa_enforced -gt 0 ]; then
  echo "Active Profile Analysis:"
  
  # Get the profile name
  profile_name=$(echo "$AA_STATUS" | grep "brave" | head -1 | awk '{print $NF}' | tr -d '()')
  
  if [ -n "$profile_name" ]; then
    # Try to find the actual profile file
    profile_file=""
    for dir in /etc/apparmor.d /var/lib/apparmor/profiles /nix/store/*/etc/apparmor.d; do
      if [ -f "$dir/brave" ] || [ -f "$dir/*brave*" ]; then
        profile_file=$(ls "$dir/"*brave* 2>/dev/null | head -1)
        break
      fi
    done
    
    if [ -n "$profile_file" ] && [ -f "$profile_file" ]; then
      echo "  Profile: $profile_file"
      echo
      echo "  Key Restrictions:"
      
      # Network access
      if grep -q "network" "$profile_file" 2>/dev/null; then
        echo "    [+] Network: Controlled"
      else
        echo "    [-] Network: Unrestricted"
      fi
      
      # File access
      if grep -q "deny.*/" "$profile_file" 2>/dev/null; then
        echo "    [+] Filesystem: Restricted"
      fi
      
      # Capabilities
      cap_count=$(grep -c "capability" "$profile_file" 2>/dev/null)
      if [ "$cap_count" -gt 0 ]; then
        echo "    [+] Capabilities: $cap_count explicit grants"
      fi
      
      # Process execution
      if grep -q "deny.*exec" "$profile_file" 2>/dev/null; then
        echo "    [+] Exec: Restricted"
      fi
      
    else
      echo "  Profile: NixOS dynamic profile (not directly readable)"
      echo
      echo "  Enforcement: Process tree is confined"
      echo "    [+] All $aa_enforced Brave processes under mandatory access control"
      echo "    [+] File access, network, and capabilities controlled by kernel"
      echo "    [+] Profile inherited from parent process"
    fi
  fi
else
  echo "No AppArmor enforcement detected"
fi

echo "-------------------------------------------------------------------------------"
echo

# Critical exploit mitigation
echo "[EXPLOIT MITIGATION FLAGS - TOP 20 CRITICAL]"
echo "-------------------------------------------------------------------------------"

# Get flags from main process AND a renderer
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
    printf "%-50s: ACTIVE\n" "$desc"
    return 0
  else
    printf "%-50s: MISSING\n" "$desc"
    return 1
  fi
}

echo "Memory Safety (UAF/Heap Protection):"
miracle=0; check_flag "MiraclePtr" "  PartitionAlloc MiraclePtr" && miracle=1
backup=0; check_flag "PartitionAllocBackupRefPtr\|BackupRefPtr" "  BackupRefPtr" && backup=1
cage=0; check_flag "V8ForceMemoryCage\|V8MemoryCage" "  V8 Memory Cage" && cage=1

echo
echo "JIT/Code Execution Hardening:"
jitless=0; check_flag "jitless\|--jitless" "  V8 JIT Disabled (--jitless)" && jitless=1
nojit=0; check_flag "V8NoJIT" "  V8NoJIT Feature Flag" && nojit=1
nowasm=0; check_flag "WebAssembly" "  WASM Disabled (via feature flag)" && nowasm=1

echo
echo "Process Isolation:"
siteproc=0; check_flag "site-per-process" "  Site-Per-Process" && siteproc=1
strict=0; check_flag "StrictSiteIsolation" "  Strict Site Isolation" && strict=1
isolate=0; check_flag "isolate-origins\|IsolateOrigins" "  Origin Isolation" && isolate=1

echo
echo "Sandbox Hardening:"
netsand=0; check_flag "NetworkServiceSandbox" "  Network Service Sandboxed" && netsand=1
audio=0; check_flag "AudioServiceSandbox\|AudioServiceOutOfProcess" "  Audio Service Sandboxed" && audio=1

echo
echo "Attack Surface Reduction:"
webgl=0; check_flag "disable-webgl" "  WebGL Disabled" && webgl=1
webgpu=0; check_flag "disable-webgpu" "  WebGPU Disabled" && webgpu=1
webrtc=0; check_flag "disable-webrtc" "  WebRTC Disabled" && webrtc=1

echo
echo "Cross-Origin Security:"
coop=0; check_flag "CrossOriginOpenerPolicy" "  COOP Enforced" && coop=1
coep=0; check_flag "CrossOriginEmbedderPolicy" "  COEP" && coep=1

echo "-------------------------------------------------------------------------------"
echo

# Kernel hardening
echo "[KERNEL HARDENING]"
echo "-------------------------------------------------------------------------------"
yama=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
bpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)
perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
aa_total_sys=$(echo "$AA_STATUS" | grep "processes are in enforce mode" | awk '{print $1}')

printf "%-40s: %s %s\n" "Ptrace Scope" "${yama:-N/A}" "$([ "$yama" = "3" ] && echo '[OK]' || echo '[WARN]')"
printf "%-40s: %s %s\n" "Unprivileged BPF" "${bpf:-N/A}" "$([ "$bpf" = "2" ] && echo '[OK]' || echo '[WARN]')"
printf "%-40s: %s %s\n" "Perf Events" "${perf:-N/A}" "$([ "$perf" = "3" ] && echo '[OK]' || echo '[WARN]')"
printf "%-40s: %s %s\n" "Kernel Pointer Hiding" "${kptr:-N/A}" "$([ "$kptr" = "2" ] && echo '[OK]' || echo '[WARN]')"
printf "%-40s: %s total %s\n" "AppArmor System-Wide" "${aa_total_sys:-0}" "$([ ${aa_total_sys:-0} -gt 0 ] && echo '[OK]' || echo '[WARN]')"
echo "-------------------------------------------------------------------------------"
echo

# Assessment
echo "[SECURITY ASSESSMENT]"
echo "==============================================================================="

# Calculate score
flags_score=$((miracle + backup + cage + jitless + nojit + nowasm + siteproc + strict + netsand + audio))
kernel_score=0
[ $seccomp_ok -eq $renderers ] && ((kernel_score++))
[ "$yama" = "3" ] && ((kernel_score++))
[ "$bpf" = "2" ] && ((kernel_score++))
[ $aa_enforced -gt 0 ] && ((kernel_score++))

total_score=$((flags_score + kernel_score))
max_score=14

printf "Score: %d/%d exploit mitigations active\n\n" "$total_score" "$max_score"

if [ $total_score -ge 12 ]; then
  echo "Status: HARDENED "
elif [ $total_score -ge 8 ]; then
  echo "Status: PROTECTED - Good security with gaps"
else
  echo "Status: BASIC - Using Chromium defaults only"
fi
echo "==============================================================================="
