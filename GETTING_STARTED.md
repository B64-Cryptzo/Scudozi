# Getting Started

This guide helps anyone run Scudozi quickly on stage or locally.

## What You Need

- Git
- Go (for fallback/non-Nix run)
- Nix (optional but recommended for reproducible demo flow)

---

## Windows

### Recommended: WSL + Nix

#### 1. Install WSL (PowerShell as Administrator)

```powershell
wsl --install -d Ubuntu
```

Reboot if prompted. Open Ubuntu and complete first-time setup.

#### 2. Install Nix inside WSL Ubuntu

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Restart the WSL terminal, then verify:

```bash
nix --version
```

#### 3. Run Scudozi

```bash
cd /mnt/c/Users/EnzoGenovese/Documents/Scudozi
nix run .
```

#### 4. Get Login Credentials

```bash
cat /tmp/scudozi-demo-creds.txt
```

Open `http://localhost:8080` in your Windows browser.

### Fallback (No Nix)

From Git Bash or PowerShell in repo root:

```bash
go run .
cat ./scudozi-demo-creds.txt
```

---

## macOS

### Install Nix

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Restart terminal, verify:

```bash
nix --version
```

### Run Scudozi

```bash
nix run .
cat /tmp/scudozi-demo-creds.txt
```

Open `http://localhost:8080`.

### Fallback (No Nix)

```bash
go run .
cat ./scudozi-demo-creds.txt
```

---

## Linux

### Install Nix

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Restart shell, verify:

```bash
nix --version
```

### Run Scudozi

```bash
nix run .
cat /tmp/scudozi-demo-creds.txt
```

Open `http://localhost:8080`.

### Fallback (No Nix)

```bash
go run .
cat ./scudozi-demo-creds.txt
```

---

## Demo Quick Check (All OS)

1. Start service (`nix run .` or `go run .`)
2. Read generated credentials file
3. Sign in at `http://localhost:8080`
4. Start a temporary listener to see graph updates:

```bash
python -m http.server 8000 --bind 0.0.0.0
```

5. Verify node appears and details update.

---

## Optional: Fixed Demo Credentials

If you want stable credentials during a live demo:

```bash
SCUDOZI_DEMO_USER=demo-admin SCUDOZI_DEMO_PASS='DemoPass123!' nix run .
```

Or with Go:

```bash
SCUDOZI_DEMO_USER=demo-admin SCUDOZI_DEMO_PASS='DemoPass123!' go run .
```
