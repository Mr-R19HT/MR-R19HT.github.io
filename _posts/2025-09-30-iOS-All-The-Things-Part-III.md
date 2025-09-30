---
date: 2025-09-30 19:48:15
layout: post
title: iOS All The Things - Part II

description: 
image: /assets/img/ios-pentesting/Part-III/cover-test-III.jpeg
optimized_image: /assets/img/ios-pentesting/Part-III/cover-test-III.jpeg
category: blog
tags:
  - iOS Pentesting
  - IOS Penetration Testing
  - frida
  - objection
  - iOS Reverse Engineering
  - Caches
  - logs
  - iOS Basics
---

# Agenda of iOS Pentesting:
1. [Intro](#intro)
2. [Runtime Manipulation](#runtime-manipulation)
3. [iOS Reverse Engineering](#ios-reverse-engineering)
4. [Network Communication](#network-communication)
5. [Cache & Logs](#cache--logs)
6. [Conclusion](conclusion)

## Intro

Now, in Part 3, we put that knowledge to the test. This is where we transition from passive observation to active engagement, performing a real-world penetration test against an iOS application.

Our journey will take us deep inside the application's runtime behavior, where we'll learn to manipulate it in real-time with powerful tools like Frida and Objection. We will then reverse engineer its binary to uncover hidden logic and vulnerabilities. We'll intercept and dissect its network communications, and finally, we'll scour its cached data and logs for exposed sensitive information.
