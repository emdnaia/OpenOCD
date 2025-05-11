#############################################################################
# /etc/nixos/hardening.nix  – “paranoid” desktop bundle (Graphene malloc)   #
#############################################################################

# inspired by https://github.com/cynicsketch/nix-mineral

{ pkgs, lib, ... }:

let
  # Pull the *unstable* channel – you already have <unstable> in configuration.nix
  unstable     = import <unstable> { config.allowUnfree = true; };

  # Graphene hardened malloc lives only in unstable for now
  graphenePkg  = unstable.graphene-hardened-malloc;
in
{
  ###########################################################################
  # 0. Up-stream “hardened” profile  (AppArmor + Scudo + hardened kernel)
  ###########################################################################
  imports = [ <nixpkgs/nixos/modules/profiles/hardened.nix> ];

  ###########################################################################
  # 1. Extra run-time hardening knobs
  ###########################################################################
  boot.kernel.sysctl = {
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
  };

  ###########################################################################
  # 2. Boot-time parameters   (add IBT here ↓↓↓)
  ###########################################################################
  boot.kernelParams = [
    # wipe pages on alloc/free (info-leak mitigation)
    "init_on_alloc=1" "init_on_free=1"

    # lockdown LSM – even root can’t touch /dev/mem, load unsigned FW …
    "lockdown=confidentiality"

    # Extra CFI: Indirect-Branch Tracking (CET)
    "ibt=on"

    # (optional) Shadow-Stack – uncomment to try it out
    "shstk=on"

    # Uncomment if you want AMD IOMMU only; otherwise leave auto-probe
    # "amd_iommu=on,pt"
  ];

  ###########################################################################
  # 3. (optional) user namespaces
  ###########################################################################
  # security.allowUserNamespaces = true;

  ###########################################################################
  # 4. (optional) swap AppArmor → SELinux (start permissive!)
  ###########################################################################
  # security.apparmor.enable = lib.mkForce false;
  # security.selinux = {
  #   enable        = true;
  #   policy        = "targeted";   # or "minimum", "mls"
  #   enforcing     = false;        # permissive first – check AVC logs!
  #   relabelOnBoot = true;
  # };

  ###########################################################################
  # 5. Switch the whole system to Graphene hardened_malloc
  ###########################################################################
  environment.memoryAllocator.provider = "graphene-hardened";
}

# if buggy check nvidia via
#dmesg -T | grep -A3 -B3 nvidia
