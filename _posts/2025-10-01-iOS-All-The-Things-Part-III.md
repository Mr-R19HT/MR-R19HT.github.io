---
date: 2025-10-01 23:08:15
layout: post
title: iOS All The Things - Part III

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

## Runtime Manipulation: Mastering Frida & Objection

In iOS penetration testing, Runtime Manipulation is one of the most powerful techniques at your disposal. It allows you to interact with and modify a running application without needing its original source code. This is where Frida and Objection become essential tools in your arsenal.

This requires a physical USB connection between your jailbroken iOS device and your Linux machine, which serves as the vital link for tools like Frida to control the target application.

**Basic Workflow:**

a. Start the target app on your jailbroken device.

b. Inject Frida scripts to hook into interesting functions.

c. OR Use Objection for quick security assessment and bypasses.

d. Monitor and manipulate the app's behavior in real-time

#### Frida

It is a dynamic instrumentation toolkit. In simple terms, it lets you inject your own scripts into running applications. Think of it as giving you a "remote control" for any app. you can:

* Change what the app does while it's running.
* Bypass security checks (like pinning or root detection).
* Monitor function calls and method arguments.
* Modify return values of functions.

Once you have a Frida script running inside an application, you can interact with the Objective-C runtime, which is the backbone of most iOS apps. This is incredibly powerful for discovering and manipulating the app's classes and methods on the fly.

```bash
// -U: Connect to a USB device
// -f: Spawn the app with this package name
// -n: Attach to the process with this name

frida -U -f com.highaltitudehacks.DVIAswiftv2 -n 'DVIA-v2'
```

**Here are fundamental commands:**

![image](/assets/img/ios-pentesting/Part-III/objc-frida.png)

* `ObjC.available`: This is a crucial check you should perform at the beginning of your scripts. It returns true if the Objective-C runtime is accessible within the target process, and false if it is not. This confirms you are in the right context before trying to execute any other Objective-C commands.

* `ObjC.classes`: This command provides a goldmine of information. It returns a list of all Objective-C classes currently loaded in the application's memory. This is your starting point for understanding the app's structure and finding interesting targets to hook and manipulate.

* 
