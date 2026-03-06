# Getting Started

This guide is for anyone running Scudozi from:

- a local clone
- or directly from GitHub: `github:B64-Cryptzo/Scudozi`

## Prerequisites

- Internet access to fetch Nix inputs and Go dependencies
- Permission to bind port `8080` (or your configured port)
- Permission to terminate processes for **Kill Process**:
  - Linux/macOS may require `sudo` for some targets
  - Windows may require an elevated terminal for protected targets

## Enable Required Nix Features Once

```bash
mkdir -p ~/.config/nix
cat >> ~/.config/nix/nix.conf <<'EOF'
experimental-features = nix-command flakes
EOF
```

Verify:

```bash
nix --extra-experimental-features "nix-command flakes" --version
```

---

## Fastest Run (Any OS with Nix)

```bash
nix --extra-experimental-features "nix-command flakes" run github:B64-Cryptzo/Scudozi
```

Then open `http://localhost:8080`.

Get startup credentials:

```bash
cat /tmp/scudozi-demo-creds.txt
```

Tail JSON audit log:

```bash
tail -f /tmp/scudozi.log
```

---

## Windows

### Recommended: WSL2 Ubuntu + Nix

1. Install WSL2 (PowerShell as Administrator):

```powershell
wsl --install -d Ubuntu
```

2. Inside Ubuntu, install Nix:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

3. Clone repo to a template path and enter it:

```bash
git clone https://github.com/B64-Cryptzo/Scudozi.git ~/projects/scudozi
cd ~/projects/scudozi
```

4. If your repo is under `/mnt/<drive>/...`, mark it safe in WSL Git:

```bash
git config --global --add safe.directory /mnt/<drive>/Users/<windows-user>/<path-to-repo>
```

5. Run:

```bash
nix --extra-experimental-features "nix-command flakes" run .
cat /tmp/scudozi-demo-creds.txt
tail -f /tmp/scudozi.log
```

### Native Windows fallback (no Nix)

```powershell
go run .
Get-Content .\scudozi-demo-creds.txt
Get-Content .\scudozi.log -Wait
```

---

## macOS

1. Install Nix:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

2. Clone and run:

```bash
git clone https://github.com/B64-Cryptzo/Scudozi.git ~/projects/scudozi
cd ~/projects/scudozi
nix --extra-experimental-features "nix-command flakes" run .
```

3. Credentials and logs:

```bash
cat /tmp/scudozi-demo-creds.txt
tail -f /tmp/scudozi.log
```

---

## Linux

1. Install Nix:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

2. Clone and run:

```bash
git clone https://github.com/B64-Cryptzo/Scudozi.git ~/projects/scudozi
cd ~/projects/scudozi
nix --extra-experimental-features "nix-command flakes" run .
```

3. Credentials and logs:

```bash
cat /tmp/scudozi-demo-creds.txt
tail -f /tmp/scudozi.log
```

---

## Local Development

```bash
nix --extra-experimental-features "nix-command flakes" develop
go run .
```

Without Nix:

```bash
go run .
```

---

## Demo-Friendly Runtime Flags

Use these when your host has few open listeners (common in WSL):

```bash
go run . --demo-services --demo-services-count 5
# or
nix --extra-experimental-features "nix-command flakes" run . -- --demo-services --demo-services-count 5
```

Custom audit log location:

```bash
go run . --log-file ./scudozi.log
# or
nix --extra-experimental-features "nix-command flakes" run . -- --log-file ./scudozi.log
```

Also stream audit log to stdout:

```bash
go run . --log-stdout
```

---

## Stable Demo Credentials (Optional)

Set fixed credentials for stage demos:

```bash
SCUDOZI_DEMO_USER=demo-admin SCUDOZI_DEMO_PASS='DemoPass123!' nix --extra-experimental-features "nix-command flakes" run .
```

Or without Nix:

```bash
SCUDOZI_DEMO_USER=demo-admin SCUDOZI_DEMO_PASS='DemoPass123!' go run .
```

---

## Quick Verification Checklist

1. Start Scudozi
2. Read generated credentials file
3. Login succeeds on `http://localhost:8080`
4. `GET /graph` updates every refresh cycle in UI
5. Audit entries appear in log file
6. `--demo-services` shows extra nodes and allows simulated kill flow for `demo-*` services
