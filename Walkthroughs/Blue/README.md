# Blue

## Overview

Deploy & hack into a Windows machine, leveraging common misconfigurations issues.

## Walkthrough

Running an initial Nmap scan against the hosts finds 4 ports are declared open:

```console
$ nmap -p- -T4 10.10.84.100 -oN scans/initial.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-03 21:39 GMT
Nmap scan report for 10.10.84.100
Host is up (0.034s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
```

Running a full scan against these ports finds that the host is running Windows 7 with SMB operating on ports 139/445:

```console
$ nmap -p 135,139,445,3389 -T4 -A 10.10.84.100 -oN scans/open_ports.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-03 21:50 GMT
Nmap scan report for 10.10.84.100
Host is up (0.030s latency).

PORT     STATE SERVICE     VERSION
135/tcp  open  msrpc       Microsoft Windows RPC
139/tcp  open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp  open             Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 Professional SP1 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 8.1 Update 1 (96%), Microsoft Windows Vista SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows Server 2008 R2 SP1 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:8e:79:93:61:d9 (unknown)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h59m59s, deviation: 3h27m50s, median: 0s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-12-03T15:50:29-06:00
| smb2-time: 
|   date: 2023-12-03T21:50:29
|_  start_date: 2023-12-03T21:36:41
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   27.75 ms 10.8.0.1
2   28.14 ms 10.10.84.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.20 seconds
```


![Blue - MSF Search](/images/blue_msf_search.png)

![Blue - RHOSTS](/images/blue_rhosts.png)

![](blue_exploit.png)

-----

## Recon

1. Scan the machine.

```
No answer needed
```

2. How many ports are open with a port number under 1000?

```
3
```

3. What is this machine vulnerable to?

```
MS17-010
```

## Gain Access

1. Start Metasploit

```
No answer needed
```

2. Find the exploitation code we will run against the machine. What is the full path of the code?

```

```

3. Show options and set the one required. What is the name of this value?

```

```

4. Run the exploit!

```
No answer neededsea
```

5. Confirm the exploit has run correctly!

```
No answer needed
```

## Escalate


## Cracking


## Find flags!


