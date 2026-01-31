# AD-Reaper

A comprehensive Active Directory enumeration tool.

`AD-Reaper` helps with everything from getting an **initial foothold** (finding null sessions) to **authenticated auditing** (finding privilege escalation paths). It combines anonymous enumeration techniques with deeper authenticated scanning and post-scan analysis.

Created while doing various CTFs, mainly in the hopes that it will assist me while doing the CPTS and OSCP exams. The primary purpose of this tool was to facilitate initial access, address memory gaps, and streamline my workflow.

## Modes & Features

### Anonymous Mode (Default)

Run without credentials to find your initial entry point. This mode aggressively targets low-hanging fruit.

- **Null Session Hunting:** Automatically tries both `''` and `.` usernames to bypass weak null session filters on SMB and SAMR.
- **Recursive SMB Walking:** If a null session is found, it recursively walks directories to find sensitive files (e.g., `web.config`, `passwords.txt`) if the `--spider-shares` flag is used.
- **Hybrid User Enumeration:** Generates a master user list by combining anonymous LDAP queries (active users) with RPC/SAMR enumeration (all users/RIDs).
- **Server Object Discovery:** Identifies high-value infrastructure (Domain Controllers, File Servers) via anonymous LDAP queries.
- **AS-REP Roasting:** Automatically tests the discovered user list for accounts that do not require Kerberos pre-authentication and dumps the hashes.

### Authenticated Mode

Run with credentials (password or NTLM hash) to audit privileges, find attack paths, and identify misconfigurations.

- **Access Auditing:**
  - **SMB:** Lists accessible shares and performs an **active write check** (creates/deletes a temp file) to confirm true permissions.
  - **Remote Access:** Checks for open paths via WinRM (5985), RDP (3389), and WMI (135), correlating them with group memberships.
  - **WMI Execution:** Validates credentials against DCOM to confirm if tools like `wmiexec.py` will work.
- **LDAP & Misconfigurations:**
  - **LAPS & Modern LAPS:** Checks for both legacy (`ms-Mcs-AdmPwd`) and modern (`msLAPS-Password`) cleartext passwords.
  - **Delegation:** Identifies accounts with Unconstrained Delegation.
  - **High-Value Targets:** explicitly hunts for privileged accounts where `adminCount=1`.
  - **ADCS Detection:** Passively identifies Active Directory Certificate Services (ADCS) infrastructure via SPN analysis.
  - **Groups:** Dumps full group memberships, including primary groups.
- **Attack Primitives:**
  - **Kerberoasting:** Identifies user accounts with SPNs and attempts Kerberoasting.
  - **Pass-the-Hash:** Full support for NTLM hash authentication (`-H`).

### Actionable Intelligence

The tool now includes a suggestions engine. Based on the scan findings, it generates copy-paste ready commands for follow-up attacks using standard tools:

- **Certipy** (if ADCS is detected)
- **NetExec/Kerbrute** (if user enumeration failed)
- **Evil-WinRM/PsExec** (if LAPS or Admin access is found)

## Installation

1. Clone the repository:

   ```bash
   git clone [https://github.com/mermehr/ad-reaper.git](https://github.com/mermehr/ad-reaper.git)
   cd ad-reaper
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install the required Python modules:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
positional arguments:
  target                DC IP

options:
  -h, --help            show this help message and exit

Authentication:
  -u, --username USERNAME
                        domain\user or user@domain
  -p, --password PASSWORD
                        password
  -H, --hashes HASHES   LM:NT hash
  -d, --domain DOMAIN   Force domain name (useful when discovery fails)

Roasting & Output:
  --hash-format {john,hashcat}
  -o, --output OUTPUT   Output dir for logs and hashes (default: reaper-logs)
  --no-logging          Disable file logging (logs and hashes)
  --users-file USERS_FILE
                        Target only these users for AS-REP roasting
  --rc4-only            Force RC4 for Kerberoasting
  --no-roast            Report roastable users without requesting tickets
  --jitter JITTER       Delay (seconds) jitter for roasting requests (evasion)
  --spider-shares       Recursively list files on accessible SMB shares (anonymous)

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

**Do not** run this if your goal is evasion.

## Contributing

Pull requests are welcome. This tool was built to handle the "nuances" of different Windows Server configurations. If you find it fails on a specific box, feel free to open an issue or PR.

## Preview

![session](https://raw.githubusercontent.com/mermehr/media/main/2026/01/upgit_20260117_1768657485.gif)
