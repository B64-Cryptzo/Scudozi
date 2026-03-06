{ config, lib, pkgs, ... }:
let
  cfg = config.services.scudozi;
  package = if cfg.package == null then (if pkgs ? scudozi then pkgs.scudozi else null) else cfg.package;
in
{
  options.services.scudozi = {
    enable = lib.mkEnableOption "Scudozi self-hosted security visibility service";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Scudozi package to run. Defaults to pkgs.scudozi when available.";
    };

    address = lib.mkOption {
      type = lib.types.str;
      default = ":8080";
      description = "Listen address passed as SCUDOZI_ADDR (e.g. :8080 or 0.0.0.0:8080).";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open firewall for the configured port.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Firewall port to open for Scudozi.";
    };

    credsFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/scudozi/credentials.txt";
      description = "Path where generated (or fixed demo) credentials are written at startup.";
    };

    demoUsername = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional fixed demo username (SCUDOZI_DEMO_USER).";
    };

    demoPassword = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional fixed demo password (SCUDOZI_DEMO_PASS).";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = package != null;
        message = "services.scudozi.package is null and pkgs.scudozi is unavailable. Set services.scudozi.package explicitly from your flake package.";
      }
    ];

    users.users.scudozi = {
      isSystemUser = true;
      group = "scudozi";
      home = "/var/lib/scudozi";
      createHome = true;
    };

    users.groups.scudozi = {};

    systemd.services.scudozi = {
      description = "Scudozi Security Dashboard";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        User = "scudozi";
        Group = "scudozi";
        ExecStart = "${package}/bin/scudozi";
        Restart = "on-failure";
        RestartSec = 3;
        WorkingDirectory = "/var/lib/scudozi";
        StateDirectory = "scudozi";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
      };

      environment = {
        SCUDOZI_ADDR = cfg.address;
        SCUDOZI_CREDS_FILE = cfg.credsFile;
      }
      // lib.optionalAttrs (cfg.demoUsername != null) {
        SCUDOZI_DEMO_USER = cfg.demoUsername;
      }
      // lib.optionalAttrs (cfg.demoPassword != null) {
        SCUDOZI_DEMO_PASS = cfg.demoPassword;
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}

