# AD-Reaper

A comprehensive multi-protocol Active Directory (LDAP, SMB, SAMR) enumeration tool.

`AD-Reaper` helps with from getting an **initial foothold** (finding null sessions) to **authenticated auditing** (finding privilege escalation paths). It combines anonymous enumeration techniques with deeper authenticated scanning and post-scan analysis.

**Not a wrapper**, no external tooling needed. Script relies on `impacket` and `ldap3` libraries for enumeration, `pyasn1` library for handling structure and serialization of data.

Designed to capture and report low hanging fruit fast, with very few dependencies.

## Modes & Features

- **Null Session Hunting:** Automatically tries both `''` and `.` usernames to bypass weak null session filters on SMB and SAMR.
- **Share Auditing:** Checks permissions across all discovered shares and attempts to identify writeable directories.
- **Recursive SMB Walking:** Walks directories to find sensitive files (e.g., `web.config`, `passwords.txt`) if the `--spider-shares` flag is used.
- **Hybrid User Enumeration:** Generates a master user list by combining anonymous LDAP queries (active users) with RPC/SAMR enumeration (all users/RIDs).
- **Group Policy & Object Auditing:** Identifies interesting group memberships and misconfiguration. (Auth mode)
- **Server Object Discovery:** Identifies high-value infrastructure (Domain Controllers, File Servers) via anonymous LDAP queries.
- **Other AD Checks:** Looks other common misconfigurations that may be exploitable (ACDS, LAPS, admincount, delegations, etc.).
- **Post-Scan Analysis:** Provides actionable suggestions based on the findings (e.g., reminding you to check for GPP passwords or suggesting specific `secretsdump` targets).
- **AS-REP Roasting:** Automatically tests the discovered user list for accounts that do not require Kerberos pre-authentication and dumps the hashes. (Anon mode)
- **Kerberoasting:** Automatically identifies service accounts (SPNs) and requests TGS tickets for offline cracking. (Auth mode)

## Installation

1. Clone the repository:

   ```bash
   git clone [https://github.com/yourusername/ad-reaper.git](https://github.com/yourusername/ad-reaper.git)
   cd ad-reaper
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
usage: ad-reaper.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASHES] [-d DOMAIN]
                    [--hash-format {john,hashcat}] [-o OUTPUT] [--no-logging]
                    [--users-file USERS_FILE] [--rc4-only] [--no-roast]
                    [--jitter JITTER] [--spider-shares]
                    target

Active Directory Reaper: High-Speed Enumeration & Roasting

positional arguments:
  target                Target IP or hostname (Domain Controller)

options:
  -h, --help            show this help message and exit

Authentication:
  -u USERNAME, --username USERNAME
                        Username (format: [domain/]user)
  -p PASSWORD, --password PASSWORD
                        Password
  -H HASHES, --hashes HASHES
                        NTLM hashes (format: [LM:]NT)
  -d DOMAIN, --domain DOMAIN
                        Force domain name (useful when discovery fails)

Roasting & Output:
  --hash-format {john,hashcat}
  -o, --output OUTPUT   Output dir for logs and hashes (default: reaper-logs)
  --no-logging          Disable file logging (logs and hashes)
  --users-file USERS_FILE
                        Target only these users for AS-REP roasting
  --rc4-only            Force RC4 for Kerberoasting
  --no-roast            Report roastable users without requesting tickets
  --jitter JITTER       Delay (seconds) jitter for roasting requests (evasion)
  --spider-shares       Recursively list files on accessible SMB shares

Examples:
  Anonymous scan:
    python ad-reaper.py 10.10.10.10

  Auth + targeted roasting:
    python ad-reaper.py 10.10.10.10 -u corp.local/jdavis -p Winter2025 --users-file interesting_users.txt --rc4-only

  PTH + output dir:
    python ad-reaper.py 10.10.10.10 -u Administrator -H aad3b...:31d6... --output loot
```

## OpSec

**This tool is loud.**

- It touches the disk (SMB write checks).
- It generates significant LDAP and RPC traffic.
- It attempts Kerberos authentication against many users.

**Do not** run this if your goal is evasion. It is designed for efficiency and speed during assessments where "getting caught" by an EDR/SIEM is expected or part of the test.

---

## Preview

**Anonymous:**

![anon](assets/anon.gif)

**Authenticated:**

![auth](assets/auth.gif)
