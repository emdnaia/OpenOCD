#############################################################################
# /etc/nixos/hardening.nix  – “paranoid” desktop bundle (Graphene malloc)   #
#############################################################################
# inspired by cynicsketch/nix-mineral 

{ pkgs, lib, ... }:

let
  # Unstable channel (you already have <unstable> in configuration.nix)
  unstable     = import <unstable> { config.allowUnfree = true; };

  # Graphene hardened_malloc lives only in unstable for now
  graphenePkg  = unstable.graphene-hardened-malloc;
in
{
  ###########################################################################
  # 0.  Up-stream “hardened” profile  (AppArmor + Scudo + hardened kernel)
  ###########################################################################
  imports = [ <nixpkgs/nixos/modules/profiles/hardened.nix> ];

  ###########################################################################
  # 1.  Extra run-time hardening knobs
  ###########################################################################
  boot.kernel.sysctl = {
   ## ── existing ───────────────────────────────
    "fs.protected_fifos"                = 2;
    "fs.protected_regular"              = 2;
    "kernel.unprivileged_bpf_disabled"  = 2;
    "kernel.perf_event_paranoid"        = 3;
    "kernel.yama.ptrace_scope"          = 3;
    "vm.mmap_rnd_bits"                  = 32;
    "vm.mmap_rnd_compat_bits"           = 16;
    "kernel.kexec_load_disabled"        = 1;
    "kernel.kcore_restrict"             = 2;
    "kernel.randomize_kstack_offset"    = 2;
    "kernel.sysrq"                      = 4;
    "kernel.kptr_restrict"              = 2;
    "net.ipv4.tcp_syncookies"           = 1;
    "net.core.bpf_jit_harden"           = 2;
    "net.core.bpf_jit_kallsyms"         = 0;
    "fs.memfd_noexec"                   = 1;
    "vm.unprivileged_userfaultfd"       = 0;
    "vm.max_map_count"                  = 1048576;

    ## ── new, low-risk additions ───────────────
    # Link-file protections
    "fs.protected_symlinks"             = 1;
    "fs.protected_hardlinks"            = 1;

    # Kernel log & panic behaviour
    "kernel.dmesg_restrict"             = 1;
    "kernel.panic_on_oops"              = 1;
    "kernel.panic"                      = 10;
    "kernel.ctrl-alt-del"               = 0;

    # eBPF: disable JIT compiler
    "net.core.bpf_jit_enable"           = 0;

#    # Anti-spoof / anti-redirect (IPv4 + IPv6)
#    "net.ipv4.conf.all.accept_redirects"      = 0;
#    "net.ipv4.conf.default.accept_redirects"  = 0;
#    "net.ipv6.conf.all.accept_redirects"      = 0;
#    "net.ipv6.conf.default.accept_redirects"  = 0;
#    "net.ipv4.conf.all.secure_redirects"      = 0;
#    "net.ipv4.conf.default.secure_redirects"  = 0;
#    "net.ipv4.conf.all.send_redirects"        = 0;
#    "net.ipv4.conf.default.send_redirects"    = 0;
#
#    # Source-route & martian filtering
#    "net.ipv4.conf.all.accept_source_route"   = 0;
#    "net.ipv4.conf.default.accept_source_route" = 0;
#    "net.ipv6.conf.all.accept_source_route"   = 0;
#    "net.ipv6.conf.default.accept_source_route" = 0;
#    "net.ipv4.conf.all.log_martians"          = 1;
#
#    # Strict reverse-path validation
#    "net.ipv4.conf.all.rp_filter"             = 1;
#    "net.ipv4.conf.default.rp_filter"         = 1;
#
#    # TIME-WAIT assassination mitigation
#    "net.ipv4.tcp_rfc1337"                    = 1;

# Uncomment if you want AMD IOMMU only; otherwise let the kernel probe
# "amd_iommu=on,pt"

  ];

  ###########################################################################
  # 3.  (optional) user namespaces
  ###########################################################################
  # security.allowUserNamespaces = true;

  ###########################################################################
  # 4.  todo someday: swap AppArmor to SELinux (start permissive!)
  ###########################################################################
  # security.apparmor.enable = lib.mkForce false;
  # security.selinux = {
  #   enable        = true;
  #   policy        = "targeted";   # or "minimum", "mls"
  #   enforcing     = false;        # permissive first – check AVC logs!
  #   relabelOnBoot = true;
  # };

  ###########################################################################
  # 5.  Switch the whole system to Graphene hardened_malloc
  ###########################################################################
  environment.memoryAllocator.provider = "graphene-hardened";

  ###########################################################################
  # 6. todo someday: bravaparanoid wrapper 
#  ###########################################################################
#  nixpkgs.overlays = [
#  (final: prev:
#    let
#      hmLight = "${graphenePkg}/lib/libhardened_malloc-light.so";
#      braveReal = "${prev.brave}/bin/brave";          # the real ELF
#
#      # A. paranoid – use the *light* allocator
#      braveParanoid = prev.writeShellScriptBin "brave-paranoid" ''
#        exec env -u LD_PRELOAD \
#          LD_PRELOAD=${hmLight}:${"$"}{LD_PRELOAD:-} \
#          ${braveReal} \
#            --user-data-dir="$HOME/.config/brave-paranoid" \
#            --no-first-run \
#            --enable-features=IsolateOrigins,StrictSiteIsolation,BlockInsecurePrivateNetworkRequests \
#            --disable-features=BackForwardCache \
#            --js-flags="--jitless --liftoff --no-wasm-tier-up" \
#            "$@"
#      '';
#
#      # B. hardened flags, *no* external allocator
#      braveHardened = prev.writeShellScriptBin "brave-hardened" ''
#        exec ${braveReal} \
#            --user-data-dir="$HOME/.config/brave-hardened" \
#            --no-first-run \
#            --enable-features=IsolateOrigins,StrictSiteIsolation,BlockInsecurePrivateNetworkRequests \
#            --disable-features=BackForwardCache \
#            --js-flags="--jitless --liftoff --no-wasm-tier-up" \
#            "$@"
#      '';
#    in
#    {
#      inherit braveParanoid braveHardened;
#    })
#];
#
## expose them system-wide
#environment.systemPackages = with pkgs; [ braveParanoid braveHardened ];

  ###########################################################################
  # 7. todo someday: secureboot / lurk here: https://wiki.cachyos.org/configuration/secure_boot_setup/
  ###########################################################################
  # boot.loader.systemd-boot.enable     = true;
  # boot.loader.systemd-boot.secureBoot = true;  # enrol with sbctl
  # security.tpm2.enable                = true;
# }

}
