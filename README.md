# Scudozi

Scudozi is a self-hosted security visibility dashboard for local infrastructure. It scans listening TCP services, classifies bind scope and likely reachability, and visualizes the attack surface in a browser.

For OS-specific setup instructions, see [GETTING_STARTED.md](./GETTING_STARTED.md).

## What This Project Does

- Scans local listeners across Windows/Linux/macOS
- Classifies each service by:
  - `bind_scope` (`localhost_only`, `lan_only`, `all_interfaces`, etc.)
  - `likely_reachability` (`local_only`, `lan_reachable`, `potentially_external`, etc.)
- Shows a live graph and service details for security triage
- Includes on-screen risk filters, scan-change summary, and per-node remediation guidance
- Supports authenticated process termination with step-up verification

## Why It Matters For Self-Hosting

Self-hosters often expose services unintentionally (wrong bind address, bad interface choice, stale firewall assumptions). Scudozi makes those mistakes visible quickly and locally, without cloud dependence.

Use cases:
- Validate what is actually listening before exposing reverse proxy routes
- Catch accidental `0.0.0.0` bindings
- Explain service exposure to teammates with a visual graph

## Why Nix Makes It Reproducible

This repo includes:
- `flake.nix` for reproducible build/dev/run
- NixOS module (`nix/module.nix`) for service deployment

Benefits:
- Same binary from same source everywhere
- One-command run with `nix run`
- Declarative systemd + firewall config with NixOS

## Quick Start (Under 2 Minutes)

### Option A: Local run with Nix

```bash
nix --extra-experimental-features "nix-command flakes" run .
```

Then open `http://localhost:8080`.

At startup, Scudozi prints SRP credentials and writes them to:

```text
/tmp/scudozi-demo-creds.txt
```

Use those credentials on the login screen.

### Option B: Dev shell

```bash
nix --extra-experimental-features "nix-command flakes" develop
go run .
```

## 2-3 Minute Demo Scenario

1. **Start service**
   - `nix --extra-experimental-features "nix-command flakes" run .`
2. **Open dashboard + sign in**
   - `cat /tmp/scudozi-demo-creds.txt`
   - login in browser
3. **Trigger a visible listener**
   - start a temporary local web server (`python -m http.server 8000 --bind 0.0.0.0`)
4. **Refresh/observe**
   - watch new node appear with scope/reachability classification
5. **Show policy control**
   - select node and use step-up verification for kill action
   - demo services (`demo-*`) use simulated termination so stage demos do not kill host processes
6. **Show reproducible deployment story**
   - point to NixOS module below

If your host has few/no listeners (common in WSL), run with demo nodes:

```bash
nix --extra-experimental-features "nix-command flakes" run . -- --demo-services --demo-services-count 5
```

## NixOS Service Deployment

Import this flake module and enable:

```nix
{
  inputs.scudozi.url = "github:B64-Cryptzo/Scudozi";

  outputs = { self, nixpkgs, scudozi, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        scudozi.nixosModules.default
        ({ ... }: {
          services.scudozi.enable = true;
          services.scudozi.package = scudozi.packages.x86_64-linux.default;
          services.scudozi.address = ":8080";
          services.scudozi.port = 8080;
          services.scudozi.openFirewall = true;

          # Optional fixed creds for stage demos:
          # services.scudozi.demoUsername = "demo-admin";
          # services.scudozi.demoPassword = "demo-pass";
        })
      ];
    };
  };
}
```

Useful options:
- `services.scudozi.enable`
- `services.scudozi.package`
- `services.scudozi.address`
- `services.scudozi.port`
- `services.scudozi.openFirewall`
- `services.scudozi.credsFile`
- `services.scudozi.demoUsername`
- `services.scudozi.demoPassword`

## Repository Layout

```text
.
+- cmd/server/main.go
+- internal/server/
+- graph/
+- scanner/
+- site/index.html
+- flake.nix
+- nix/module.nix
+- main.go
+- README.md
+- GETTING_STARTED.md
```

## Security Notes

- Dashboard is gated by SRP login
- Access session uses short-lived cookie protections (`HttpOnly`, `SameSite=Strict`, max-age 12h)
- CSRF protection on state-changing endpoints
- Step-up verification token required for kill operations
- Audit events are emitted as JSON lines (`SCUDOZI_LOG_FILE`)
- Health/runtime endpoints are available: `/healthz`, `/readyz`, `/version`

## Commands

```bash
# Build
nix --extra-experimental-features "nix-command flakes" build .

# Run local flake
nix --extra-experimental-features "nix-command flakes" run .

# Run directly from GitHub
nix --extra-experimental-features "nix-command flakes" run github:B64-Cryptzo/Scudozi

# Development shell
nix --extra-experimental-features "nix-command flakes" develop

# Demo nodes for empty hosts (WSL/stage)
nix --extra-experimental-features "nix-command flakes" run . -- --demo-services --demo-services-count 5

# Optional custom audit log path
nix --extra-experimental-features "nix-command flakes" run . -- --log-file ./scudozi.log
```
