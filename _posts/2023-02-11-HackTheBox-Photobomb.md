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
Use `nano` to open this file and put ip.

```bash
nano /etc/hosts
```
![image](/assets/img/htb/photobomb/nano1.png)

