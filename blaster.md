# Blaster
> Silver Garcia

## Enumeration
Nmap
```bash
└─$ sudo nmap -T4 -A -p- -Pn 10.10.138.216
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 12:06 EDT
Nmap scan report for 10.10.138.216
Host is up (0.26s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-04-17T16:18:42+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-04-16T16:04:49
|_Not valid after:  2024-10-16T16:04:49
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-04-17T16:18:37+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -2s, deviation: 0s, median: -2s
```

Directory enumeration
```
└─# gobuster dir --url http://10.10.138.216/ --wordlist /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.138.216/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2024/04/17 16:30:02 Starting gobuster in directory enumeration mode
===============================================================
/retro                (Status: 301) [Size: 150] [--> http://10.10.138.216/retro/]
Progress: 19112 / 20470 (93.37%)===============================================================
```

Credentials found by looking at the /retro blog:
wade:parzival

## Getting access

Got access through RDP using found credentials/

## Privilege Escalation
Got system privileges abusing CVE-2019-1388
