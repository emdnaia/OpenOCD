# NixOS Secure Boot with Lanzaboote

Without Secure Boot, an attacker with root can write to `/boot`, drop a backdoored initrd, and wait for reboot. 

## Pre-Flight Checks
```bash
mokutil --sb-state      # Check Secure Boot status (probably disabled)
sbctl status        # Check sbctl 
```
## Step 1: Add Lanzaboote
```bash
# Verify latest release
curl -s https://api.github.com/repos/nix-community/lanzaboote/releases/latest | jq '{tag: .tag_name, date: .published_at}'

# Add with niv
cd /etc/nixos
doas niv init                                    # skip if nix/sources.json exists
doas niv add nix-community/lanzaboote -r v1.0.0  # "already exists" = OK

# Verify pinned version
cat nix/sources.json | jq '.lanzaboote.rev'
# Should show: "v1.0.0"
```

## Step 2: Edit configuration.nix

### Add to `let` block:
```nix
let
  sources = import ./nix/sources.nix;
  lanzaboote = import sources.lanzaboote;
in
```

### Add to `imports`:
```nix
imports = [
  ./hardware-configuration.nix
  lanzaboote.nixosModules.lanzaboote
];
```

### Add sbctl to system packages:
```nix
environment.systemPackages = with pkgs; [
  sbctl  # For managing Secure Boot keys
];
```

### Disable systemd-boot, enable Lanzaboote:
```nix
boot.loader.systemd-boot.enable = lib.mkForce false;

boot.lanzaboote = {
  enable = true;
  pkiBundle = "/var/lib/sbctl";
};

# Optional - limit generations to save ESP space
boot.loader.systemd-boot.configurationLimit = 3;
```

## Step 3: Generate Keys & Rebuild
```bash
doas sbctl create-keys
doas nixos-rebuild switch
```

## Step 4: BIOS Setup

1. Reboot → Enter BIOS (F2/F12/DEL/ESC)
2. Secure Boot → Custom Mode
3. Clear/Delete all keys (enters Setup Mode)
4. **DISABLE Secure Boot** (important for enrollment)
5. Save & exit → Boot NixOS

## Step 5: Enroll Keys
```bash

# now pick one #

#### option 1 #### 
# your keys
# doas sbctl enroll-keys

####  option 2 #### 
#  Microsoft keys (make sure 
doas sbctl enroll-keys --microsoft

# Verify enrollment
doas sbctl status
```

## Step 6: Enable Secure Boot

1. Reboot → BIOS
2. **ENABLE Secure Boot**
3. Save & exit

## Step 7: Verify
```bash
mokutil --sb-state          # Should say: SecureBoot enabled
doas sbctl verify           # All files should show ✓
bootctl status              # Shows Secure Boot: enabled (user)
```

## Troubleshooting

### ESP Disk Full
```bash
doas rm -rf /boot/EFI/nixos/ /boot/EFI/Linux/ /boot/loader/entries/
df -h /boot
doas nixos-rebuild switch --install-bootloader
```

### Unsigned Files After Rebuild
```bash
doas sbctl sign -s /boot/EFI/nixos/kernel-*.efi
doas sbctl verify
```

### Won't Boot After Enabling Secure Boot

1. BIOS → Disable Secure Boot
2. Boot NixOS
3. `doas sbctl enroll-keys --microsoft`
4. BIOS → Enable Secure Boot

## Post-Setup Hardening (Optional)

Add to kernel params for additional protection:
```nix
boot.kernelParams = [
# iommu hardening y/n
  "iommu=force"
  "iommu.passthrough=0"
  "iommu.strict=1"
  "intel_iommu=on"
  
# sign modules y/n   
  "module.sig_enforce=1"
];

security.lockKernelModules = true;
```

## Quick Reference
```bash
mokutil --sb-state              # Secure Boot status
doas sbctl verify               # Check signatures
doas sbctl status               # Key enrollment status
bootctl status                  # Boot chain info
ls /var/lib/sbctl/keys/         # Your keys location
```
