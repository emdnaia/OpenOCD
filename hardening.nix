#############################################################################
# /etc/nixos/hardening.nix  – “paranoid++” desktop bundle (Graphene malloc) #
# inspired by cynicsketch/nix-mineral
# experimental May 2025 test version
#############################################################################

{ pkgs, lib, ... }:

let
  # Unstable channel – needed for graphene-hardened-malloc.
  unstable     = import <unstable> { config.allowUnfree = true; };

  # Graphene allocator package path.
  graphenePkg  = unstable.graphene-hardened-malloc;
in
{
  ###########################################################################
  # 0.  Up-stream “hardened” NixOS profile  (AppArmor + Scudo + hardened LTS)
  ###########################################################################
  imports = [ <nixpkgs/nixos/modules/profiles/hardened.nix> ];

  ###########################################################################
  # 1.  Extra run-time hardening knobs  (sysctl)
  ###########################################################################
  boot.kernel.sysctl = {
   ## ── existing ──────────────────────────────────────────────────────────
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

    "fs.protected_symlinks"             = 1;
    "fs.protected_hardlinks"            = 1;
    "kernel.dmesg_restrict"             = 1;
    "kernel.panic_on_oops"              = 1;
    "kernel.panic"                      = 10;
    "kernel.ctrl-alt-del"               = 0;
    "net.core.bpf_jit_enable"           = 0;   

   # + those 2 settings will be breaking flatpaks
   # "kernel.unprivileged_userns_clone"  = 0;   # kill unpriv user-ns
   # "user.max_user_namespaces"          = 0;
   # +- those 2 settings will be breaking flatpaks

    "fs.suid_dumpable"                  = 0;   # never write core dumps
    "kernel.core_pattern"               = "|/bin/false";
  # "kernel.random.trust_cpu"           = 0;   # distrust CPU-built RNG
    "vm.panic_on_oom"                   = 1;   # fail hard on OOM


#    "net.ipv4.conf.all.accept_redirects"      = 0;
#    "net.ipv4.conf.default.accept_redirects"  = 0;
#    "net.ipv6.conf.all.accept_redirects"      = 0;
#    "net.ipv6.conf.default.accept_redirects"  = 0;
#    "net.ipv4.conf.all.secure_redirects"      = 0;
#    "net.ipv4.conf.default.secure_redirects"  = 0;
#    "net.ipv4.conf.all.send_redirects"        = 0;
#    "net.ipv4.conf.default.send_redirects"    = 0;
#
#    "net.ipv4.conf.all.accept_source_route"   = 0;
#    "net.ipv4.conf.default.accept_source_route" = 0;
#    "net.ipv6.conf.all.accept_source_route"   = 0;
#    "net.ipv6.conf.default.accept_source_route" = 0;
#
#    "net.ipv4.conf.all.log_martians"          = 1;
#
#    # Strict reverse-path validation
#    "net.ipv4.conf.all.rp_filter"             = 1;
#    "net.ipv4.conf.default.rp_filter"         = 1;
#
#    # TIME-WAIT assassination mitigation
#    "net.ipv4.tcp_rfc1337"                    = 1;

  };

  ################################################
  # 2. Boot-time kernel parameters
  ################################################
  boot.kernelParams = [
    # existing
    "init_on_alloc=1" "init_on_free=1"
    "lockdown=confidentiality"
    "ibt=on" "shstk=on" "lam=on" "l1d_flush=on"
    "slab_nomerge" "page_alloc.shuffle=1"

    # heap sanity (≈5 % hit)
    "slub_debug=FZP" "page_poison=1"

    # Spectre/BHI mitigations
    "spectre_v2=on" "spec_store_bypass_disable=on"
  # ---- performance hits ----
  #  "nosmt"                  # disable hyper-thread siblings
  #  "tsx=off"                # kill Intel TSX
  # ---- performance hits ----
    "spectre_bhi=on"
    "srso=on"
    # -----------------------
    # Landlock stacked with existing LSMs
    "lsm=landlock,lockdown,yama,apparmor"
  ];

# 2.5 Kernel modules cannot be loaded, removed, or modified after boot
  security.lockKernelModules = true;

  ###########################################################################
  # 3.  Disable unprivileged user namespaces globally
  ###########################################################################
 # security.allowUserNamespaces = lib.mkForce false;

  ###########################################################################
  # 4.  todo switch AppArmor to SELinux (start permissive!)
  ###########################################################################
  # security.apparmor.enable = lib.mkForce false;
  # security.selinux = {
  #   enable        = true;
  #   policy        = "targeted";   # or "minimum", "mls"
  #   enforcing     = false;        # permissive first – check AVC logs!
  #   relabelOnBoot = true;
  # };

  ###########################################################################
  # 5.  System-wide Graphene hardened_malloc
  ###########################################################################
  environment.memoryAllocator.provider = "graphene-hardened";

#  ###########################################################################
#  # 6.  todo: Hardened Brave wrappers – GPU / WebGL / WebGPU fully disabled
#  ###########################################################################
#  nixpkgs.overlays = [
#    (final: prev:
#      let
#        hmLight    = "${graphenePkg}/lib/libhardened_malloc-light.so";
#        braveReal  = "${prev.brave}/bin/brave";  # upstream Brave ELF
#
#        # A. paranoid – Brave + light allocator + GPU fully off
#        braveParanoid = prev.writeShellScriptBin "brave-paranoid" ''
#          exec env -u LD_PRELOAD \
#            LD_PRELOAD=${hmLight}:${"$"}{LD_PRELOAD:-} \
#            ${braveReal} \
#              --user-data-dir="$HOME/.config/brave-paranoid" \
#              --no-first-run \
#              --disable-gpu --disable-3d-apis --disable-webgl --disable-webgpu \
#              --enable-features=IsolateOrigins,StrictSiteIsolation,BlockInsecurePrivateNetworkRequests \
#              --disable-features=BackForwardCache,UseWebP \
#              --js-flags="--jitless --liftoff --no-wasm-tier-up" \
#              "$@"
#        '';
#
#        # B. hardened flags, *no* external allocator
#        braveHardened = prev.writeShellScriptBin "brave-hardened" ''
#          exec ${braveReal} \
#              --user-data-dir="$HOME/.config/brave-hardened" \
#              --no-first-run \
#              --disable-gpu --disable-3d-apis --disable-webgl --disable-webgpu \
#              --enable-features=IsolateOrigins,StrictSiteIsolation,BlockInsecurePrivateNetworkRequests \
#              --disable-features=BackForwardCache,UseWebP \
#              --js-flags="--jitless --liftoff --no-wasm-tier-up" \
#              "$@"
#        '';
#      in
#      {
#        inherit braveParanoid braveHardened;
#      })
#  ];
#
  # Expose the wrappers system-wide
#  environment.systemPackages = with pkgs; [ braveParanoid braveHardened ];

  ###########################################################################
  # 7.  todo: Secure Boot / TPM2 (optional, requires manual key enrolment) 
  # lurk here: https://wiki.cachyos.org/configuration/secure_boot_setup/
  # faster via: https://github.com/nix-community/lanzaboote/releases
  ###########################################################################
  # boot.loader.systemd-boot.enable     = true;
  # boot.loader.systemd-boot.secureBoot = true;  # enrol with `sbctl`
  # security.tpm2.enable                = true;
}

