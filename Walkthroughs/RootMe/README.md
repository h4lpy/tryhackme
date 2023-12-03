# RootMe
## Overview

A ctf for beginners, can you root me?

Room link: https://tryhackme.com/room/rootme
Difficulty: **Easy**

## Walkthrough

Running an initial scan against all ports shows ports 22 (SSH) and 80 (HTTP) are open.

```console
$ nmap -p- -T4 <VICTIM IP> -oN scans/initial.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-21 22:47 GMT
Nmap scan report for <VICTIM IP>
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.79 seconds
```v  -00fgv

Running a full scan against these ports show Apache version `2.4.29` is running on an Ubuntu system:

```console
$ nmap -p 22,80 -T4 -A <VICTIM IP> -oN scans/open_ports.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-21 22:49 GMT
Nmap scan report for <VICTIM IP>
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%), Linux 3.2 - 4.9 (93%), Linux 3.7 - 3.10 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   31.44 ms 10.9.0.1
2   31.54 ms <VICTIM IP>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.75 seconds
```

Navigating to the website shows a basic terminal prompt design:

![RootMe - Homepage](/images/rootme_homepage.png)

Running GoBuster identifies an `/uploads` and a `/panel` directory:

```console
$ gobuster dir -u http://<VICTIM IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![RootMe - Hidden Directory](/images/rootme_hidden_directory.png)

Navigating to `/panel` shows an upload form:

![RootMe - Upload Form](/images/rootme_upload_form.png)

Trying to upload a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell) errors out, as follows:

![RootMe - PHP Invalid](/images/rootme_php_invalid.png)

Changing the file extension from `.php` to `.php5` manages to succeed:

![RootMe - PHP5 Valid](/images/rootme_php5_valid.png)

Navigating to `/uploads/php-reverse-shell.php5`, we receive a callback on our Netcat listener as the `www-data` user:

![RootMe - Callback](/images/rootme_callback.png)

Manually crawling through the filesystem yields a `user.txt` in `/var/www`:

![RootMe - User.txt](/images/rootme_user_txt.png)

Looking for files with the SUID bit set finds `/usr/bin/python`:

```console
$ find / -type f -perm -4000 2>/dev/null
```

![RootMe - SUID Python](/images/rootme_setuid_python.png)

Can run the [GTFOBin](https://gtfobins.github.io/gtfobins/python/#suid) for Python SUID to escalate privileges and get the `root.txt` flag:

![RootMe - Privesc](/images/rootme_privesc.png)

-----

## Reconnaissance

1. Scan the machine, how many ports are open?

```
2
```

2. What version of Apache is running?

```
2.4.29
```

3. What service is running on port 22?

```
SSH
```

4. Find directories on the web server using the GoBuster tool.

```
No answer needed
```

5. What is the hidden directory?

```
/panel/
```

## Getting a Shell

1. user.txt

```
THM{y0u_g0t_a_sh3ll}
```

## Privilege Escalation

1. Search for files with SUID permissions, which file is weird?

```
/usr/bin/python
```

2. Find a form to escalate your privileges.

```
No answer needed
```

3. root.txt

```
THM{pr1v1l3g3_3sc4l4t10n}
```