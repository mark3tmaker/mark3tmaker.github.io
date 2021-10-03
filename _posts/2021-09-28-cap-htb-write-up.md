---
title: Cap - Hack the Box Write-Up
published: true
---
**Difficulty**: Easy. **OS**: Linux.

Ok, so this was my first machine I ever resolved in HTB. This was quite simple machine, but also really helpful to get started. Recently retired from HTB.

Let's get into it!

### Intrusion

The machine has 10.10.10.245 ip address. Nmap was used to scan ports and enumeration.

```
nmap -p- --open -Pn -v 10.10.10.245 -oN allPorts
```
![](./media/cap/nmap-scan.png)

Ports 21, 22, 80 were found open. Let's see more about the services running on these ports.
```
nmap -p21,22,80 -sV -sC 10.10.10.245 -oN targeted
```
![](./media/cap/nmap-enum.png)



User _anonymous_ was not useful to login via FTP without credentials. The http server running in port 80 looks like this:

![](./media/cap/http-server.png)

Inspecting a little bit the web application, specifically on "Security Snapshot" field, it redirects randomly to a direction where is hosted a **.pcap** file that contains network traffic data:

![](./media/cap/pcap-data.png)

The **.pcap** file hosted in `http://10.10.10.245/data/0` contains FTP login credentials inside. Wireshark was used to analyze traffic data:

```
wireshark 0.pcap
```
![](./media/cap/wireshark.png)

These credentials also was useful to log in via SSH.

![](./media/cap/SSH.png)

Ok, intrusion done. We see user's flag.

![](./media/cap/user-flag.png)

### Privilege Escalation

First I was looking for SUID permissions, Crontab tasks or processes executed by root user without founding anything useful. Finally (Doing allusion to the Machine's name) I've searched for capabilities of binaries from "/" directory.

```
getcap -r / 2>/dev/null
```
![](./media/cap/capabilities.png)

A capability of type "SUID" were found on python3.8 binary. Let's try to exploit it to get a shell as root user.

```
python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```
![](./media/cap/exploit.png)

It worked! Now we see root's flag.

![](./media/cap/root-flag.png)

### Conclusion

Although this machine was quite simple, I think that the priority should be to find sensitive exposed data, then try to exploit vulnerabilities of current services (I was in that rabbit hole for a while). As i said earlier, very nice machine to get started. Salud!
