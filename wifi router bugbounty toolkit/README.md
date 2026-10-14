# WiFi Router Bug Bounty Toolkit

**Coded by Cyber Security Engineer Mr Sabaz Ali Khan**

A defensive, authorized Wi-Fi/router security-audit toolkit for testing a router that you own or are explicitly authorized to assess.

## Features

- Router reachability check
- Safe TCP service enumeration with Nmap
- HTTP/HTTPS response-header inspection
- Local Wi-Fi information through NetworkManager/iw
- Manual security-hardening checklist
- Timestamped text reports
- No password cracking, deauthentication, exploit delivery, persistence, or destructive actions

## Requirements

Linux is recommended.

Optional tools:

- `bash`
- `nmap`
- `curl`
- `ping`
- `nmcli` or `iw`

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y nmap curl iputils-ping network-manager iw
```

## Usage

```bash
chmod +x wifi-audit.sh
./wifi-audit.sh 192.168.1.1
```

Reports are written to `./reports/`.

Custom report directory:

```bash
OUTDIR=./my-reports ./wifi-audit.sh 192.168.1.1
```

## Suggested authorized workflow

1. Confirm the router belongs to you or obtain written authorization.
2. Record router model, firmware version, and test scope.
3. Run the audit from the local network.
4. Review exposed services.
5. Inspect router security settings manually.
6. Compare firmware against the vendor's official security advisories.
7. Document each finding with evidence, impact, reproduction conditions, and remediation.
8. Retest after remediation.

## Finding template

```text
Title:
Affected router/model:
Firmware:
Asset/IP:
Severity:
Preconditions:
Description:
Evidence:
Reproduction steps:
Security impact:
Recommended remediation:
Retest result:
Date:
```

## Safety

Use only against systems you own or are explicitly authorized to test. Do not use this project to access, disrupt, intercept, or degrade third-party networks.

## License

MIT License. See `LICENSE.md`.
