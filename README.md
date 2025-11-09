# Null-Reaper

A fast, multi-protocol Active Directory enumerator for low-hanging fruit.

`Null-Reaper` is a specialized enumeration tool for pentesters, students, and red teamers. It was born from the frustration of running multiple different commands to find one tiny misconfiguration.

Instead of a "kitchen sink," this tool is a "workflow." It does one thing well: it chains together the most common **anonymous** and **null session** vulnerabilities into a single, fast scan to find your initial foothold.

It's noisy by design and built to "do the DC dirty" where stealth is not a concern.

## Key Features

* **Multi-Protocol Null Sessions:** Automatically tries both `''` (standard) and `.` (Samba `map to guest`) usernames to bypass weak null session filters on both SMB and SAMR.
* **Recursive SMB Share Enumeration:** On a successful null session, it doesn't just list shares. It recursively walks all accessible directories and highlights sensitive files (e.g., `Groups.xml`, `.ini`, `password*.txt`).
* **Rich Domain Info:** Dumps high-level Domain Controller information (FQDN, functional levels, etc.) from the RootDSE via anonymous LDAP.
* **Hybrid User Enumeration:** Gets a *complete* user list by combining two methods:
    1.  **LDAP:** Finds *active, non-system* users.
    2.  **SAMR (RPC):** Dumps *all* users (including disabled and hidden) and filters out common system junk.
* **Active Attack Module:** Automatically feeds the combined, de-duplicated master user list into an active **AS-REP Roasting** check to find vulnerable accounts.

---

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/mermehr/null-reaper.git
    cd null-reaper
    ```

2.  (Recommended) Create and activate a virtual environment:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  Install the required Python modules:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

The script is built around a simple `[target] [module]` structure. If no module is provided, it runs **all** of them.

```bash
usage: null-reaper.py [-h] target [module]

A specialized, multi-protocol AD Enumeration Tool for null sessions.

positional arguments:
  target      The target IP address.
  module      The module to run (smb, dcinfo, roast). Scans all if omitted.

options:
  -h, --help  show this help message and exit

    Examples:
      Scan all modules (default):
        python null-reaper.py target

      Scan only for open SMB shares and files:
        python null-reaper.py target smb

      Get DC info and enumerate users (LDAP + SAMR):
        python null-reaper.py target dcinfo

      Enumerate users and actively test for AS-REP Roasting:
        python null-reaper.py target roast
```

---

## This Tool is LOUD

This cannot be stressed enough. `Null-Reaper` is an **active scanner** that generates a significant amount of "malicious" network traffic by design:
* Anonymous LDAP queries
* Anonymous RPC/SAMR enumeration
* Full recursive SMB file listing
* Multiple Kerberos AS-REQ requests

**Do not** run this on an environment where you are trying to be stealthy. It is intended for situations where noise is not a primary concern.

---

## Contributing

Pull requests are welcome. This tool was built to find "nuances," and it can only be tested on a limited number of machines. If you find it fails on a specific box or you have a new "nuance" to add, feel free to open an issue or PR.

---

## License

This project is licensed under the MIT License.
