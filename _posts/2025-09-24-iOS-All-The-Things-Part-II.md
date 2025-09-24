---
date: 2025-09-24 16:24:15
layout: post
title: iOS All The Things - Part II

description: 
image: /assets/img/ios-pentesting/Part-II/cover-test.jpeg
optimized_image: /assets/img/ios-pentesting/Part-II/cover-test.jpeg
category: blog
tags:
  - iOS Pentesting
  - IOS Penetration Testing
  - jailbreak
  - burpsuite on ios
  - iOS Basics
---

# Agenda of iOS Pentesting:
1. [Intro](#intro)
2. [Types of Jailbreaking](#types-of-jailbreaking)
3. [Push & Pull IPA Packages](#push-&-pull-ipa-packages)
4. [Setup Burpsuite](#setup-burpsuite)
5. [Tools](#tools)
6. [Conclusion](#conclusion)

## Intro
Before we can start using advanced penetration testing tools on an actual iPhone, we need to address a fundamental barrier: Apple's strict security controls. These controls, while great for user safety, limit our ability to inspect a running system. This is where jailbreaking comes in.

**Jailbreaking** is the process of removing these software restrictions imposed by Apple. It gives you root access (administrator-level control) to the iOS operating system. This allows you to:

* Install applications from outside the official App Store.
* Customize the operating system's look and feel.
* Most importantly for us: Run powerful security tools that can analyze other apps and the system itself.

**Jailbreaking** exploits vulnerabilities (security weaknesses) in the iOS code to bypass Apple's security layers. The goal is always the same: to break the "chain of trust" and gain the ability to run unsigned code.

The general process can be summarized in the following chart:

![image](/assets/img/ios-pentesting/Part-II/jailbreak-process-chart2.png)

Here’s the breakdown:

a. **Exploit a Vulnerability:** The jailbreak tool uses a specific bug or combination of bugs in the iOS software. These can be in the web browser (a "browser-based" exploit) or in a file the device opens.
b. **Bypass Security Protections:** The exploit is used to bypass the two main security features:
      * Code Signing: This allows the device to run the jailbreak's own code, which is not signed by Apple.
      * Sandbox: This escapes the app's restricted container, giving the code access to the entire filesystem.
c. **Patch the Kernel:** The "kernel" is the core of the operating system. The jailbreak modifies it in memory to permanently disable the security checks (like code signing enforcement) while the device is running.
d. **Install Persistence and a Package Manager:** Finally, the tool installs a "package manager" like Cydia or Sileo. This is an alternative app store specifically for installing tweaks and command-line tools (like those we need for pentesting). It also adds a helper to re-apply the jailbreak after a device reboot (since the kernel patches are not permanent by default).

For a penetration tester, a jailbroken device is a laboratory. It is the equivalent of having administrative access on a target server. It allows us to:

* Intercept network traffic (SSL Pinning).
* Analyze and modify app data at runtime.
* Dump decrypted application binaries for static analysis.
* See the real-time behavior of the operating system.

## Types of Jailbreaking

Not all jailbreaks are created equal. The main difference between them lies in what happens when you restart the device. This characteristic of the jailbreak's ability to survive a reboot. It is categorized into four main types.

The following chart illustrates how each type behaves during a device reboot:

![image](/assets/img/ios-pentesting/Part-II/types-jailbreak-chart.png)

Here’s the breakdown:

a. **UnTethered:** if reboot the device, the ios is still jailbreaking.
b. **Tethered:** if reboot the device, the ios is return to normal status(means not jailbreak).
c. **Semi-Tethered:** This type of jailbreak allows a user to reboot their phone normally, but upon doing so, the jailbreak and any modified code will be effectively disabled, as it will have an unpatched kernel. (need to do re-jailbreak because not open in optima stage in jailbreak ).
d. **Semi-Untethered:** if reboot the device , the ios is return to normal status but the device have ipa package can use it to do jailbreak again without using any cables.

> **Important Tip:** A semi-untethered jailbreak is often the best choice because it allows for maximum flexibility. If your testing causes a device crash and reboot, you can quickly re-enable the jailbreak directly from the device without needing to be near a computer, ensuring you can get back to work quickly.

