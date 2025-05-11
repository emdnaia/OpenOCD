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
    # Already had …
    "fs.protected_fifos"               = 2;
    "fs.protected_regular"             = 2;
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.perf_event_paranoid"       = 3;
    "kernel.yama.ptrace_scope"         = 3;
    "vm.mmap_rnd_bits"                 = 32;
    "vm.mmap_rnd_compat_bits"          = 16;
    "kernel.kexec_load_disabled"       = 1;
    "kernel.kcore_restrict"            = 2;
    "kernel.randomize_kstack_offset"   = 2;
    "kernel.sysrq"                     = 4;

    "fs.memfd_noexec"                 = 1;     
    "vm.unprivileged_userfaultfd"     = 0;
    "vm.max_map_count"                = 1048576;  
  };

  ###########################################################################
  # 2.  Boot-time parameters (CFI & friends)
  ###########################################################################
  boot.kernelParams = [
    # wipe pages on alloc/free (info-leak mitigation)
    "init_on_alloc=1" "init_on_free=1"

    # lockdown LSM – even root can’t touch /dev/mem, load unsigned firmware …
    "lockdown=confidentiality"

    # Extra CFI: Indirect-Branch Tracking  (Intel/AMD CET)
    "ibt=on"

    # (optional) Shadow-Stack – comment out if proprietary blobs crash
    "shstk=on"

    # Pointer-tagging (Intel Linear Address Masking, Alder-Lake+)
    "lam=on"

    # Flush L1D cache on privilege transitions (side-channel hardening)
    "l1d_flush=on"

    # Uncomment if you want AMD IOMMU only; otherwise let the kernel probe
    # "amd_iommu=on,pt"
  ];

  ###########################################################################
  # 3.  (optional) user namespaces
  ###########################################################################
  # security.allowUserNamespaces = true;

  ###########################################################################
  # 4.  (optional) swap AppArmor → SELinux (start permissive!)
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
