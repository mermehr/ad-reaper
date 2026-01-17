# AD-Reaper

A comprehensive Active Directory enumeration tool.

`AD-Reaper` helps with getting an **initial foothold** (finding null sessions) to **authenticated auditing** (finding privilege escalation paths). It combines anonymous enumeration techniques with deeper authenticated scanning.

Created while doing various CTFs, mainly in the hopes that it will assist me while doing the CPTS and OSCP exams. The primary purpose of this tool was to facilitate initial access, address memory gaps, and streamline my workflow.

## Modes & Features

### Anonymous Mode (Default)

Run without credentials to find your initial entry point. This mode aggressively targets low-hanging fruit.

- **Null Session Hunting:** Automatically tries both `''` and `.` usernames to bypass weak null session filters on SMB and SAMR.
- **Recursive SMB Walking:** If a null session is found, it recursively walks directories to find sensitive files (e.g., `web.config`, `passwords.txt`).
- **Hybrid User Enumeration:** Generates a master user list by combining anonymous LDAP queries (active users) with RPC/SAMR enumeration (all users/RIDs).
- **AS-REP Roasting:** Automatically tests the discovered user list for accounts that do not require Kerberos pre-authentication and dumps the hashes.

### Authenticated Mode

Run with credentials (password or NTLM hash) to audit privileges and find attack paths.

- **Access Auditing:**
  - **SMB:** Lists accessible shares and performs an **active write check** (creates/deletes a temp file) to confirm true permissions.
  - **Remote Access:** Checks for open paths via WinRM (5985), RDP (3389), and WMI (135), correlating them with group memberships.
- **LDAP:**
  - **LAPS:** Checks if the user can read cleartext LAPS passwords.
  - **Delegation:** Identifies accounts with Unconstrained Delegation.
  - **Groups:** Dumps full group memberships, including primary groups.
- **Attack Primitives:**
  - **Kerberoasting:** Identifies user accounts with SPNs and attempts Kerberoasting.
  - **Pass-the-Hash:** Full support for NTLM hash authentication (`-H`).

------

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mermehr/ad-reaper.git
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

------

## Usage

```bash
usage: ad-reaper.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASHES] [--dump-hashes]
                    [--hash-format {john,hashcat}] [--output-dir OUTPUT_DIR]
                    target

Examples:
  Run anonymous scan (null sessions, AS-REP roast, etc.):
    python ad-reaper.py 192.168.56.10

  Run authenticated scan with a password:
    python ad-reaper.py 192.168.56.10 -u 'DOMAIN/user' -p 'Password123'

  Run authenticated scan using Pass-the-Hash:
    python ad-reaper.py 172.16.10.5 -u 'Admin' -H 'aad3...:31d6...'
```

## OpSec

**This tool is loud.**

- It touches the disk (SMB write checks).
- It generates significant LDAP and RPC traffic.
- It attempts Kerberos authentication against many users.

**Do not** run this if your goal is evasion.

------

## Contributing

Pull requests are welcome. This tool was built to handle the "nuances" of different Windows Server configurations. If you find it fails on a specific box, feel free to open an issue or PR.

------

## Preview

![session](https://raw.githubusercontent.com/mermehr/media/main/2026/01/upgit_20260117_1768657485.gif)
