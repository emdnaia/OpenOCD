#############################################################################
# /etc/nixos/hardening.nix  – "paranoid++" desktop bundle (Graphene malloc) #
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
  # 0.  Up-stream "hardened" NixOS profile 
  ###########################################################################
  imports = [ <nixpkgs/nixos/modules/profiles/hardened.nix> ];

  ###########################################################################
  # 1.  Extra run-time hardening knobs  (sysctl)
  ###########################################################################
  boot.kernel.sysctl = {
   ## ── existing ─────────────────────────────────────────────────────────
  "kernel.io_uring_disabled" = 2;  # Disable io_uring (many recent CVEs)
  "dev.tty.ldisc_autoload" = 0;    # Prevent line discipline exploits
  
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
    "kernel.randomize_va_space" = 2;
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

    ## ── TODO: **testable new parameters** (now UN-commented) ──────────

    # - this will be breaking flatpaks
   # "kernel.unprivileged_userns_clone"  = 0;   # kill unpriv user-ns
   # "user.max_user_namespaces"          = 0;
    # - breaking flatpaks
   
    "fs.suid_dumpable"                  = 0;   # never write core dumps
    "kernel.core_pattern"               = "|/bin/false";
#    "kernel.random.trust_cpu"           = 0;   # distrust CPU-built RNG
    "vm.panic_on_oom"                   = 1;   # fail hard on OOM
#
#    ## ── Anti-spoof / martian / redirect filters (uncommented) ──────────
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

    # -------- End of TODO block --------
  };

  ################################################
  # 2. Boot-time kernel parameters (COMBINED WITH ADDITION 3 & 4)
  ################################################
  boot.kernelParams = [
    # existing

#  "kvm.nx_huge_pages=force"  # Mitigate iTLB multihit
#  "randomize_kstack_offset=on"  # Already have =2, but "on" is standard

    "init_on_alloc=1" "init_on_free=1"
    "lockdown=confidentiality"
    "ibt=on" "shstk=on" "lam=on" "l1d_flush=on"
    "slab_nomerge" "page_alloc.shuffle=1"

    "vsyscall=none"  # Disable legacy vsyscall table

   
    # heap sanity (≈5 % hit)
    "slub_debug=FZP" "page_poison=1"

    # Spectre/BHI mitigations
    "spectre_v2=on" "spec_store_bypass_disable=on"
    # ---- new testables ----
  #  "nosmt"                  # disable hyper-thread siblings
 #   "tsx=off"                # kill Intel TSX
    "spectre_bhi=on"
    "srso=on"
    # -----------------------
    # Landlock stacked with existing LSMs
    "lsm=landlock,lockdown,yama,apparmor"
    
    # ADDITION 3: IOMMU stricter settings
    "iommu=force"
    "iommu.passthrough=0"
    "iommu.strict=1"
    "intel_iommu=on"
    
    # ADDITION 4: Module signature enforcement
    "module.sig_enforce=1"
  ];

# Build a kernel with zero loadable module support

#   boot.kernelPatches = [{
#     name = "no-modules";
#     patch = null;
#     extraConfig = ''
#       # Disable loadable module support entirely
#       MODULES n
#     '';
#   }];
    
# security.lockKernelModules = true;
 
 ###########################################################################
  # 3.  Disable unprivileged user namespaces globally
  ###########################################################################
 # security.allowUserNamespaces = lib.mkForce false;

  ###########################################################################
  # 4.  Optional: switch from AppArmor to SELinux (start permissive!)
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
#  # ADDITION 1 & 2: Kernel hardening (FIXED - removed invalid options)
#  ###########################################################################
#  boot.kernelPatches = [
#    {
#      name = "memory-hardening";
#      patch = null;
#      extraConfig = ''
#        INIT_STACK_ALL_ZERO y
#        FORTIFY_SOURCE y
#        KFENCE y
#        KFENCE_SAMPLE_INTERVAL 100
#        RANDOMIZE_KSTACK_OFFSET y
#        SLAB_FREELIST_HARDENED y
#        SHUFFLE_PAGE_ALLOCATOR y
#        PAGE_TABLE_CHECK y
#        PAGE_TABLE_CHECK_ENFORCED y
#      '';
#    }
#  ];
#
  ###########################################################################
  # ADDITION 4: Complete module lockdown
  ###########################################################################
#  # Lock kernel modules after boot - NO module loading allowed
#  security.lockKernelModules = true;
#  
#  # List ONLY essential modules that must load at boot
#  boot.kernelModules = [ 
#    "nvidia" "nvidia_modeset" "nvidia_drm" 
#  ];
#
#  ###########################################################################
#  # ADDITION 9: Process isolation - systemd hardening
#  ###########################################################################
#  systemd.services = {
#    # Default hardening for ALL services
#    "*" = {
#      serviceConfig = {
#        # Network isolation
#        PrivateNetwork = lib.mkDefault true;
#        RestrictAddressFamilies = lib.mkDefault [ "AF_UNIX" ];
#        
#        # Filesystem isolation
#        PrivateTmp = lib.mkDefault true;
#        ProtectSystem = lib.mkDefault "strict";
#        ProtectHome = lib.mkDefault true;
#        ProtectKernelTunables = lib.mkDefault true;
#        ProtectKernelModules = lib.mkDefault true;
#        ProtectControlGroups = lib.mkDefault true;
#        ProtectKernelLogs = lib.mkDefault true;
#        ProtectClock = lib.mkDefault true;
#        ProtectProc = lib.mkDefault "invisible";
#        ProcSubset = lib.mkDefault "pid";
#        
#        # Privilege restrictions
#        NoNewPrivileges = lib.mkDefault true;
#        RestrictNamespaces = lib.mkDefault true;
#        RestrictSUIDSGID = lib.mkDefault true;
#        RemoveIPC = lib.mkDefault true;
#        PrivateDevices = lib.mkDefault true;
#        
#        # Personality/Execution restrictions
#        LockPersonality = lib.mkDefault true;
#        MemoryDenyWriteExecute = lib.mkDefault true;
#        RestrictRealtime = lib.mkDefault true;
#        SystemCallArchitectures = lib.mkDefault "native";
#        
#        # Capabilities
#        CapabilityBoundingSet = lib.mkDefault "";
#        AmbientCapabilities = lib.mkDefault "";
#        
#        # Misc hardening
#        ProtectHostname = lib.mkDefault true;
#        SystemCallFilter = lib.mkDefault [
#          "@system-service"
#          "~@privileged"
#          "~@resources"
#          "~@mount"
#          "~@reboot"
#          "~@swap"
#          "~@obsolete"
#          "~@debug"
#        ];
#      };
#    };
#    
#    # Override for services that NEED network
#    NetworkManager.serviceConfig = {
#      PrivateNetwork = lib.mkForce false;
#      RestrictAddressFamilies = lib.mkForce [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
#    };
#    
#    # Override for display manager
#    display-manager.serviceConfig = {
#      PrivateNetwork = lib.mkForce false;
#      MemoryDenyWriteExecute = lib.mkForce false;
#      PrivateDevices = lib.mkForce false;
#    };
#    
#    # Override for audio
#    pipewire.serviceConfig = {
#      PrivateNetwork = lib.mkForce false;
#      PrivateDevices = lib.mkForce false;
#      MemoryDenyWriteExecute = lib.mkForce false;
#    };
#  };
}
