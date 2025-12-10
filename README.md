# AD-Reaper

A comprehensive Active Directory enumeration tool for the modern pentester.

`AD-Reaper` streamlines the workflow from **initial foothold** (finding null sessions) to **authenticated auditing** (finding privilege escalation paths). It combines anonymous enumeration techniques with authenticated deep-dives to answer the question: *"What can I see and do with this specific access?"*

Instead of running five different tools to check for basic mis configurations, `AD-Reaper` chains them into a single, high-signal scan. Relies on `impacket` and `ldap3` python modules.

## Modes & Features

### Anonymous Mode (Default)

Run without credentials to find your initial entry point. This mode aggressively targets low-hanging fruit.

- **Null Session Hunting:** Automatically tries both `''` and `.` usernames to bypass weak null session filters on SMB and SAMR.
- **Recursive SMB Walking:** If a null session is found, it recursively walks directories to find sensitive files (e.g., `web.config`, `passwords.txt`).
- **Hybrid User Enumeration:** Generates a master user list by combining anonymous LDAP queries (active users) with RPC/SAMR enumeration (all users/RIDs).
- **AS-REP Roasting:** Automatically tests the discovered user list for accounts that do not require Kerberos pre-authentication.

### Authenticated Mode (`-u`)

Run with credentials (password or NTLM hash) to audit privileges and find attack paths.

- **Access Auditing:**
  - **SMB:** Lists accessible shares and performs an **active write check** (creates/deletes a temp file) to confirm true permissions.
  - **Remote Access:** Checks for open paths via WinRM (5985), RDP (3389), and WMI (135), correlating them with group memberships.
- **LDAP Deep-Dive:**
  - **LAPS:** Checks if the user can read cleartext LAPS passwords.
  - **Delegation:** Identifies accounts with Unconstrained Delegation.
  - **Groups:** Dumps full group memberships, including primary groups.
- **Attack Primitives:**
  - **Kerberoasting:** Identifies users with SPNs and generates `GetUserSPNs.py` syntax.
  - **Pass-the-Hash:** Full support for NTLM hash authentication (`-H`).

------

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mermehr/null-reaper.git
   cd null-reaper
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
usage: ad-reaper.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASHES] target

  Run anonymous scan (null sessions, AS-REP roast, etc.):
    python ad-reaper.py 192.168.1.100

  Run authenticated scan with a password:
    python ad-reaper.py 192.168.1.100 -u 'DOMAIN/user' -p 'Password123'

  Run authenticated scan using Pass-the-Hash:
    python ad-reaper.py 192.168.1.100 -u 'Admin' -H 'aad3...:31d6...'
```

### Automatic Suggestions

At the end of every scan, `AD-Reaper` analyzes the findings and prints **Actionable Suggestions**. These are copy-paste ready commands for tools like `Impacket`, `Certipy`, and `NetExec` to help you immediately exploit what you found.

------

## Operational Security (OpSec)

**This tool is loud.**

`AD-Reaper` is an **active scanner** designed for CTFs and engagements where noise is not a primary constraint.

- It touches the disk (SMB write checks).
- It generates significant LDAP and RPC traffic.
- It attempts Kerberos authentication against many users.

**Do not** run this if your goal is evasion.

------

## Contributing

Pull requests are welcome. This tool was built to handle the "nuances" of different Windows Server configurations. If you find it fails on a specific box, feel free to open an issue or PR.

------

## Preview

### Null scan

![screenshot](assets/anon1.png)

![screenshot](assets/anon2.png)

### Authenticated scan

![screenshot](assets/auth1.png)

![screenshot](assets/auth2.png)
