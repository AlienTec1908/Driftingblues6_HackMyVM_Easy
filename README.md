# HackMyVM: Driftingblues6 - Easy

![Driftingblues6 Icon](Driftingblues6.png)

*   **Difficulty:** Easy 🟢
*   **Author:** DarkSpirit
*   **Date:** 21. Juni 2025
*   **VM Link:** [https://hackmyvm.eu/machines/machine.php?vm=Driftingblues6](https://hackmyvm.eu/machines/machine.php?vm=Driftingblues6)
*   **Full Report (HTML):** [Link zum vollständigen Pentest-Bericht](https://alientec1908.github.io/Driftingblues6_HackMyVM_Easy/)

## Overview

This report documents the penetration testing process of the "Driftingblues6" virtual machine from HackMyVM, rated as an Easy difficulty challenge. The objective was to identify and exploit vulnerabilities to gain root access to the system. The machine featured outdated web server software and a CMS with an authenticated RCE vulnerability, coupled with a critical Kernel exploit for privilege escalation.

## Methodology

The approach involved reconnaissance to identify open services, detailed web enumeration to discover web application specifics and hidden files, exploitation of an authenticated RCE in the CMS for initial access, and finally leveraging a well-known Kernel exploit for privilege escalation.

### Reconnaissance & Web Enumeration

1.  **Host Discovery:** Identified the target IP (192.168.2.55) using `arp-scan` and configured the hostname `drifting.hmv` in `/etc/hosts`.
2.  **Port Scanning (Nmap):** Discovered only Port 80 open, running **Apache httpd 2.2.22 (Debian)**. Noted the very outdated server version.
3.  **Web Application Analysis (Curl, Nikto, Gobuster):** Confirmed Apache 2.2.22 and noted missing security headers. Discovered `/textpattern/textpattern/` (running Textpattern CMS, powered by **PHP 5.5.38**). Nikto also reported the outdated Apache and PHP versions and identified `/icons/README`. Gobuster found `robots.txt`, `index.html`, `db`, `db.png`, `spammer`, and `spammer.zip`, noting identical sizes for `db` and `db.png` and for `spammer` and `spammer.zip`.
4.  **Robots.txt Analysis:** Found a hint in `robots.txt`: "dont forget to add .zip extension to your dir-brute", confirming the approach to find zipped files.
5.  **Textpattern CMS Discovery:** Accessed `/textpattern/textpattern/` and identified the Textpattern CMS login page, noting the name "driftingblues". Verified Textpattern CMS version **v4.8.3**.

### Initial Access

Initial access was gained by compromising the Textpattern CMS admin panel using credentials found in a hidden, password-protected zip file on the webserver, and then exploiting an authenticated RCE vulnerability in the CMS.

1.  **Zip File Discovery & Cracking:** Found `spammer.zip` via Gobuster and the `robots.txt` hint. The zip file was password-protected. Used `zip2john` and `john` with `rockyou.txt` to crack the password: `myspace4`.
2.  **Credentials Disclosure:** Unzipped `spammer.zip` using the cracked password and found `creds.txt`, containing the credentials `mayer:lionheart`.
3.  **CMS Login:** Used the credentials `mayer:lionheart` to successfully log into the Textpattern CMS admin panel as user `mayer` (Publisher role).
4.  **Authenticated RCE Vulnerability:** Noted PHP timezone warnings indicating PHP 5.5.38. Discovered Textpattern CMS v4.8.3. Analyzed the CMS interface and documentation (example in an article edit page) revealing the existence of the `< txp:php >` tag for PHP code execution within templates. Identified the vulnerability: Authenticated RCE via PHP code execution in templates.
5.  **Exploiting RCE:** Used a Python exploit script (adapted for robustness) to log into Textpattern, upload a PHP webshell (`revshell.php`) via the file upload feature, and then trigger a reverse shell payload by accessing the uploaded shell.
6.  **Obtaining a Shell:** Set up a Netcat listener and triggered the webshell. Successfully obtained a reverse shell as the `www-data` user.

### Privilege Escalation

From the `www-data` shell, privilege escalation was achieved by exploiting a critical, well-known Linux Kernel vulnerability.

1.  **System Enumeration (as `www-data`):** Stabilized the shell. Checked `sudo -l` (sudo not found in PATH). Listed `/home/` (empty). Checked `/opt/` (empty). Searched for SUID binaries (`find -perm -4000`), finding `/usr/sbin/exim4` among standard ones.
2.  **Exim Version Check:** Checked Exim version (`/usr/sbin/exim4 --version`), identified it as **Exim version 4.80 #3** (2016).
3.  **Kernel Version Check:** Identified the system as Debian 7 (wheezy) with Linux Kernel **3.2.0-4-amd64**. Noted the very old Kernel.
4.  **Kernel Vulnerability Identification:** The Kernel version 3.2.x is known to be vulnerable to the critical **"Dirty COW" Local Privilege Escalation** (CVE-2016-5195).
5.  **Dirty COW Exploit:** Located a C-language Proof-of-Concept (PoC) exploit for Dirty COW (e.g., Exploit-DB 40839.c).
6.  **Exploit Transfer & Compilation:** Transferred the C exploit code to the target system's `/tmp/` directory using the `www-data` shell (`wget`, as `gcc` was available). Compiled the code on the target system (`gcc dirty.c -o pwn -pthread -lcrypt`).
7.  **Executing the Exploit:** Ran the compiled exploit (`./pwn`). The exploit modified `/etc/passwd` in memory, adding a new root user (`firefart`) with a chosen password (`benni`).
8.  **Root Access:** Used the newly created root user (`firefart`) and password (`benni`) with `su firefart` to gain a root shell.

### Flags

Both the user.txt and root.txt flags were successfully retrieved after gaining root privileges.

*   User Flag: `5355B03AF00225CFB210AE9CA8931E51` (Found in `/root/user.txt` after gaining root - *Note: Typically user flags are in user home directories, but this one was found in /root*.)
*   Root Flag: `CCAD89B795EE7BCF7BBAD5A46F40F488` (Found in `/root/root.txt`)

---

[Link zum vollständigen Pentest-Bericht](https://alientec1908.github.io/Driftingblues6_HackMyVM_Easy/)
