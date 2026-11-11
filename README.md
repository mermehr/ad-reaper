# AD-Reaper

A comprehensive multi-protocol Active Directory (LDAP, SMB, SAMR) enumeration tool.

`AD-Reaper` helps with from getting an **initial foothold** (finding null sessions) to **authenticated auditing** (finding privilege escalation paths). It combines anonymous enumeration techniques with deeper authenticated scanning and post-scan analysis.

Designed to capture and report low hanging fruit fast, with very few dependencies.

## LDAP connection behavior

AD-Reaper is built for authorized pentesting and CTF labs. Authenticated LDAP starts with plain NTLM so the scan can reveal whether the DC accepts a bind without LDAP signing or TLS.

| Option            | Attempt order                                                                     |
| ----------------- | --------------------------------------------------------------------------------- |
| Default           | Plain NTLM on 389, NTLM signing and sealing on 389, StartTLS on 389, LDAPS on 636 |
| `-s` / `--secure` | LDAPS on 636, StartTLS on 389, NTLM signing and sealing on 389, plain NTLM on 389 |

New AD deployments on Windows Server 2025 require LDAP signing by default. Effective DC policy determines whether a plain NTLM bind is accepted. Existing or upgraded domains can have different policies. See Microsoft's [LDAP signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) and [channel binding overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding).

Domain discovery uses anonymous RootDSE queries with LDAP, StartTLS and LDAPS. `-s` makes it prefer LDAPS. If discovery cannot obtain a domain, supply `-d example.local` or a qualified username such as `'EXAMPLE\tester'`. The separate anonymous enumeration mode retains its existing LDAP behavior.

## Modes & Features

- **Null Session Hunting:** Automatically tries both `''` and `.` usernames to bypass weak null session filters on SMB and SAMR.
- **Share Auditing:** Checks permissions across all discovered shares and attempts to identify writable directories.
- **Recursive SMB Walking:** Walks directories to find sensitive files (e.g., `web.config`, `passwords.txt`) if the `--spider-shares` flag is used.
- **Hybrid User Enumeration:** Generates a master user list by combining anonymous LDAP queries (active users) with RPC/SAMR enumeration (all users/RIDs).
- **Group Policy & Object Auditing:** Identifies interesting group memberships, misconfiguration and deleted objects (tombstone). (Auth mode)
- **Server Object Discovery:** Identifies high-value infrastructure (Domain Controllers, File Servers) via anonymous LDAP queries.
- **Other AD Checks:** Looks other common misconfigurations that may be exploitable (ACDS, LAPS, admincount, delegations, etc.).
- **Post-Scan Analysis:** Provides actionable suggestions based on the findings (e.g., reminding you to check for GPP passwords or suggesting specific `secretsdump` targets).
- **AS-REP Roasting:** Tests the discovered user list for accounts that do not require Kerberos pre-authentication.. (Anon mode)
- **Kerberoasting:** Identifies service accounts (SPNs).. (Auth mode)

## Installation

Supports python versions (3.12+)

- Clone the repository:

```bash
git clone https://github.com/mermehr/ad-reaper.git
cd ad-reaper
```

- Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
usage: ad-reaper.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASHES] [-d DOMAIN] [-s] [-o OUTPUT]
                    [--spider-shares]
                    target

Multi-protocol Active Directory Enumeration Tool

positional arguments:
  target                DC IP

options:
  -h, --help            show this help message and exit

Authentication:
  -u, --username USERNAME
  -p, --password PASSWORD
  -H, --hashes HASHES   LM:NT hash
  -d, --domain DOMAIN   Force domain name (useful when discovery fails)
  -s, --secure          Prefer LDAPS, then StartTLS, sealed NTLM, plain NTLM (authenticated scans)

Output & Modules:
  -o, --output OUTPUT   Output dir for logs and hashes (default: reaper-logs)
  --spider-shares       Recursively list files on accessible SMB shares

Examples:
  Anonymous scan:
    python ad-reaper.py 10.10.10.10

  Authenticated scan:
    python ad-reaper.py 10.10.10.10 -u tommy -p Spring2026
    python ad-reaper.py 10.10.10.10 -d example.local -u tommy -p Spring2026

  Prefer LDAPS with lab certificates:
    python ad-reaper.py 10.10.10.10 -d example.local -u tommy -p Spring2026 -s

  PTH + output dir:
    python ad-reaper.py 10.10.10.10 -u Administrator -H aad3b...:31d6... --output loot
```

## Preview

Authenticated scan log:

![auth_scan](./assets/auth-scale.gif)
