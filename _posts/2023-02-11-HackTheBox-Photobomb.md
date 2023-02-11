---
date: 2023-02-10 17:32:03
layout: post
title: HackTheBox - Photobomb

description: 
image: /assets/img/htb/photobomb/info.png
optimized_image: /assets/img/htb/photobomb/info.png
category: blog
tags:
  - hackthebox
  - Photobomb
  - web vulnerabilites
  - htb
  - command injection
  - basics privilege escalation
---

# Machine Information
This machine is from easy level worth 20 points.

IP: `10.10.11.182`

# Scanning and Enumeration
First thing add ip to to `/etc/hosts` file to allow any dns records.

```bash
nano /etc/hosts
```
Use `nano` to open this file and put ip.

![image](/assets/img/htb/photobomb/nano1.png)

Naturally, we will use `nmap` to identify open ports and collect some information about that machine.

```bash
nmap -A -T5 -p- 10.10.11.182
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 00:57 EST
Warning: 10.10.11.182 giving up on port because retransmission cap hit (2).
Stats: 0:01:44 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for 10.10.11.182
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   92.39 ms 10.10.14.1
2   91.01 ms 10.10.11.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 372.55 seconds
```

After scanning, I found ports 22 and 80 open, so I'll go to Website and dig deeper.

![image](/assets/img/htb/photobomb/website.png)

When you press on `Click here`, a window pops up asking you to enter your username and password.

I'm trying to bypass that popup with basic auth techniques like sql injection, default credentials (admin: admin), nosql, etc.. but all of them didn't work.

After that, I thought that I would see a source code, and I actually found the credentials.

![image](/assets/img/htb/photobomb/source.png)

Use this credentials `pH0t0:b0Mb!` to bypass that popup.

![image](/assets/img/htb/photobomb/pass.png)


