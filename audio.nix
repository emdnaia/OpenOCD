{
  # PipeWire core (graph locked at 96 kHz)
  services.pipewire = {
    enable       = true;
    alsa.enable  = true;
    pulse.enable = true;
 
    extraConfig.pipewire."10-clock-global" = {
      context.properties = {
        "default.clock.rate"          = 96000;
        "default.clock.allowed-rates" = [ 96000 ];
        "clock.force-rate"            = 96000;   # hard-lock at boot
        "resample.quality"            = 4;       # SPA best quality
        "pulse.format"                = "float32ne";
      };
    };
 
    # Session manager
    wireplumber = {
      enable = true;
 
      extraConfig."10-clock-global" = {
        wireplumber.settings = {
          "clock.rate"          = 96000;
          "clock.allowed-rates" = [ 96000 ];
          "clock.force-rate"    = 96000;
        };
      };
 
      extraConfig."monitor.bluez.properties" = {
        "bluez5.enable-aac"       = true;
        "bluez5.enable-sbc-xq"    = true;
        "bluez5.enable-msbc"      = true;
        "bluez5.enable-hw-volume" = true;
        "bluez5.roles" = [
          "a2dp_sink" "a2dp_source" "bap_sink" "bap_source"
          "hsp_hs" "hsp_ag" "hfp_hf" "hfp_ag"
        ];
      };
    };
  };
 
  # Kernel-side BT extras (LE Audio, battery reports, etc.)
  hardware.bluetooth.settings = {
    General.Experimental = true;
  };
}
