#!/usr/bin/env bash

# Re-exec with doas if not root
if [ "$EUID" -ne 0 ]; then
  exec doas "$0" "$@"
fi

# Pre-fetch all doas-requiring values
SIGNED_EFIS=$(sbctl verify 2>&1 | grep -c ✓)
MMAP_BITS=$(cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null)

echo "==============================================================================="
echo "                    NixOS HARDENED DESKTOP SECURITY AUDIT"
echo "==============================================================================="
echo

echo "=== BOOT SECURITY ==="
printf "%-20s %s\n" "Secure Boot:" "$(mokutil --sb-state 2>/dev/null | head -1)"
printf "%-20s %s\n" "Signed Boot Chain:" "$SIGNED_EFIS files"
echo

echo "=== SYSTEM ==="
printf "%-20s %s\n" "OS:" "$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
printf "%-20s %s\n" "Kernel:" "$(uname -r)"
printf "%-20s %s\n" "Profile:" "hardened"
echo

echo "=== KERNEL HARDENING ==="
printf "%-20s %s\n" "LSM Stack:" "$(cat /sys/kernel/security/lsm)"
printf "%-20s %s\n" "ASLR:" "$(cat /proc/sys/kernel/randomize_va_space) (2=full)"
printf "%-20s %s\n" "Ptrace Scope:" "$(cat /proc/sys/kernel/yama/ptrace_scope) (3=admin only)"
printf "%-20s %s\n" "Kptr Restrict:" "$(cat /proc/sys/kernel/kptr_restrict) (2=hidden)"
printf "%-20s %s\n" "Dmesg Restrict:" "$(cat /proc/sys/kernel/dmesg_restrict) (1=root only)"
printf "%-20s %s\n" "Kexec Disabled:" "$(cat /proc/sys/kernel/kexec_load_disabled)"
printf "%-20s %s\n" "Perf Paranoid:" "$(cat /proc/sys/kernel/perf_event_paranoid) (3=disabled)"
printf "%-20s %s\n" "BPF JIT:" "$(cat /proc/sys/net/core/bpf_jit_enable) (0=disabled)"
printf "%-20s %s\n" "io_uring:" "$(cat /proc/sys/kernel/io_uring_disabled) (2=disabled)"
echo

echo "=== MEMORY HARDENING ==="
printf "%-20s %s\n" "System Malloc:" "graphene-hardened"
printf "%-20s %s\n" "MMAP Rand Bits:" "$MMAP_BITS"

# Brave allocator check
if pgrep -x brave >/dev/null; then
  pid=$(pgrep -x brave | head -1)
  if cat /proc/$pid/maps 2>/dev/null | grep -q graphene; then
    printf "%-20s %s\n" "Brave Malloc:" "graphene ✓"
  else
    printf "%-20s %s\n" "Brave Malloc:" "scudo (chromium)"
  fi
fi
echo

echo "=== CPU MITIGATIONS ==="
printf "%-20s %s\n" "Spectre v2:" "$(cat /sys/devices/system/cpu/vulnerabilities/spectre_v2 | cut -d';' -f1)"
printf "%-20s %s\n" "MDS:" "$(cat /sys/devices/system/cpu/vulnerabilities/mds | cut -d';' -f1)"
printf "%-20s %s\n" "IBT:" "$(grep -q 'ibt=on' /proc/cmdline && echo 'enabled' || echo 'disabled')"
printf "%-20s %s\n" "SHSTK:" "$(grep -q 'shstk=on' /proc/cmdline && echo 'enabled' || echo 'disabled')"
echo

echo "=== DISK ==="
printf "%-20s %s\n" "LUKS Encrypted:" "yes"
echo

echo "=== BOOT PARAMS ==="
cat /proc/cmdline | tr ' ' '\n' | grep -E "lockdown|spectre|init_on|slab_|ibt=|shstk=" | sort | uniq
echo

# ============================================================================
# BRAVE BROWSER SECTION (if running)
# ============================================================================
if pgrep -f brave >/dev/null; then
  echo "==============================================================================="
  echo "                         BRAVE BROWSER HARDENING"
  echo "==============================================================================="
  echo
  
  brave_pid=$(pgrep -f "opt/brave.com/brave/brave" | head -1)
  [ -z "$brave_pid" ] && brave_pid=$(pgrep -o brave)
  renderer_pids=($(pgrep -f "type=renderer"))
  renderers=${#renderer_pids[@]}
  
  echo "=== PROCESS ISOLATION ==="
  printf "%-20s %s\n" "Renderers:" "$renderers"
  
  # Seccomp check
  seccomp_ok=0
  for pid in "${renderer_pids[@]}"; do
    [ "$(grep "^Seccomp:" /proc/$pid/status 2>/dev/null | awk '{print $2}')" = "2" ] && ((seccomp_ok++))
  done
  printf "%-20s %d/%d (%d%%)\n" "Seccomp BPF:" "$seccomp_ok" "$renderers" "$((seccomp_ok * 100 / renderers))"
  
  # Graphene in renderers
  graphene_ok=0
  for pid in "${renderer_pids[@]:0:10}"; do
    grep -q "libhardened_malloc.so" /proc/$pid/maps 2>/dev/null && ((graphene_ok++))
  done
  tested=$((renderers < 10 ? renderers : 10))
  printf "%-20s %d/%d sampled\n" "Graphene Coverage:" "$graphene_ok" "$tested"
  echo
  
  echo "=== EXPLOIT MITIGATIONS ==="
  cmdline=$(cat /proc/$brave_pid/cmdline 2>/dev/null | tr '\0' ',')
  
  check() { echo "$cmdline" | grep -qi "$1" && echo "✓" || echo "✗"; }
  
  printf "%-35s %s\n" "MiraclePtr (UAF protection):" "$(check 'MiraclePtr')"
  printf "%-35s %s\n" "BackupRefPtr:" "$(check 'BackupRefPtr')"
  printf "%-35s %s\n" "V8 Memory Cage:" "$(check 'V8ForceMemoryCage')"
  printf "%-35s %s\n" "PartitionAlloc GigaCage:" "$(check 'PartitionAllocGigaCage')"
  printf "%-35s %s\n" "Site-Per-Process:" "$(check 'site-per-process')"
  printf "%-35s %s\n" "Strict Site Isolation:" "$(check 'StrictSiteIsolation')"
  printf "%-35s %s\n" "Network Sandbox:" "$(check 'NetworkServiceSandbox')"
  printf "%-35s %s\n" "WebRTC Disabled:" "$(check 'disable-webrtc')"
  echo
  
  echo "=== MULTI-LAYER PROTECTION ==="
  printf "Layer 1: %-20s %s\n" "Graphene Malloc" "$([ $graphene_ok -gt 0 ] && echo '✓ ACTIVE' || echo '✗')"
  printf "Layer 2: %-20s %s\n" "PartitionAlloc" "$(echo "$cmdline" | grep -q 'PartitionAllocGigaCage' && echo '✓ ACTIVE' || echo '✗')"
  printf "Layer 3: %-20s %s\n" "IBT+SHSTK (HW)" "$(grep -q 'ibt=on' /proc/cmdline && echo '✓ ACTIVE' || echo '✗')"
fi

echo
echo "==============================================================================="
