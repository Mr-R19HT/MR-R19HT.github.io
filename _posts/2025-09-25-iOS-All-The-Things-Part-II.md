---
date: 2025-09-25 22:49:15
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
3. [Pull & Push IPA Packages](#pull--push-ipa-packages)
4. [Setup BurpSuite](#setup-burpsuite)
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

c. **Semi-Tethered:** This type of jailbreak allows a user to reboot their phone normally, but upon doing so, the jailbreak and any modified code will be effectively disabled, as it will have an unpatched kernel. (need to do re-jailbreak because not open in optima stage in jailbreak).

d. **Semi-Untethered:** if reboot the device , the ios is return to normal status but the device have ipa package can use it to do jailbreak again without using any cables.

> **Important Tip:** A semi-untethered jailbreak is often the best choice because it allows for maximum flexibility. If your testing causes a device crash and reboot, you can quickly re-enable the jailbreak directly from the device without needing to be near a computer, ensuring you can get back to work quickly.

Using that [website](https://canijailbreak.com/) to know what’s that tool compatible with version of ios device to make jailbreak.

## Pull & Push IPA Packages

Once your iOS device is successfully jailbroken, the next step is to install a package manager like Sileo, Cydia, or Zebra. Think of this as an "alternative App Store" specifically for jailbroken devices, where you can find powerful tools and tweaks that Apple doesn't allow.

One of the most important tools you can install is Filza File Manager. This is a powerful file explorer that gives you full access to the entire iOS filesystem. something that is normally restricted on a non-jailbroken device.

**Filza Uses:**
* Browse System Files: View and edit files across the entire operating system.
* Access App Containers: Open the sandboxed directories of installed applications.
* Extract IPA Files: This is a critical function for penetration testers.

#### How to Extract an IPA using Filza

Another meaning pull any installed app from your device for analysis:

a. Open Filza and navigate to the applications directory: '/var/containers/Bundle/Application/'

![image](/assets/img/ios-pentesting/Part-II/installed-apps-directories.jpg)

b. Find the App: You'll see folders with random names. Open each one to find the '.app' bundle for your target application (e.g., Facetime.app).

![image](/assets/img/ios-pentesting/Part-II/face-app-extension.jpg)

c. Go to any directory, such as /var/mobile/Downloads. Create a new folder named Payload. Paste the copied '.app' bundle into this Payload folder.

d. Compress the Payload folder into a ZIP file. Long-press on the Payload folder and select the "Compress" option. This will create a Payload.zip file.

![image](/assets/img/ios-pentesting/Part-II/zip-payload2.png)

e. Rename the Payload.zip file to YourAppName.ipa. An IPA file is essentially a standard ZIP archive with a specific structure and a different file extension.

![image](/assets/img/ios-pentesting/Part-II/ipa-extension.jpg)

f. The '.ipa' file is now ready for analysis. You can transfer it to your own machine (e.g., Kali Linux system) using a secure transfer tool like scp (Secure Copy).

![image](/assets/img/ios-pentesting/Part-II/shape-ipa.jpg)

To move the extracted IPA file from your iOS device to your computer, you need a connection between the two devices. This is typically done using SSH (Secure Shell).

* **Method 1:** Using SSH from Your Computer
  
  Ensure SSH is enabled on your jailbroken iOS device and that both devices are on the same network.

  ```bash
  scp mobile@[device_ip]:/var/mobile/Documents/YourAppName.ipa /path/on/your/kali/
  ```
  
* **Method 2:** Using NewTerm on Your iOS Device

  Alternatively, you can use NewTerm (available in Sileo/Zebra) a terminal emulator for iOS. to push the file to your computer:

  a.  Install NewTerm from your package manager.

  b. Open NewTerm and use scp in reverse:

  ```bash
  scp /var/mobile/Downloads/YourAppName.ipa kali@[KALI_IP]:/home/kali/Downloads/

  // The same scp command can also be used to transfer an IPA package from your computer to your jailbroken device (Push)
  scp /home/kali/Downloads/YourAppName.ipa mobile@[device_ip]:/var/mobile/Downloads/  
  ```

This ability to extract IPAs directly from a jailbroken device is a game-changer for security testing. It allows you to:

* Perform static analysis on real applications using tools like Ghidra or Hopper.
* Study the app’s compiled code, configuration files, and resources.
* Identify potential vulnerabilities without needing the original source code.

#### Analyzing Decrypted Executables with Hopper or Ghidra

After transferring an IPA package to your computer, the next step is to analyze the application's main executable file. You can extract this file by unzipping the IPA package and navigating to the 'Payload/YourApp.app' folder.

When you try to analyze an App Store application using reverse engineering tools like Hopper or Ghidra, you'll encounter a significant obstacle: the main executable file is encrypted. Apple encrypts applications from the App Store to protect intellectual property, which means static analysis tools will show garbled or meaningless code.

![image](/assets/img/ios-pentesting/Part-II/hopper-encrypted-content.png)

When an iOS application runs, the system must decrypt it in memory to execute the code.

To overcome this encryption barrier, we use 'frida-ios-dump' a powerful tool that captures a running application directly from the device's memory. Here's how it works:

a. Install frida-server from sileo.

b. Run the target application on your jailbroken device.

c. Execute [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) from your computer while the app is active.

```bash
// to forward ssh connection
iproxy 2222 22
// run frida-ios-dump 
./dump.py -H device-ip -u user -P password -p 2222 (bundle/name)
```

d. The tool dumps the decrypted version of the application from memory.

e. You now have a decrypted IPA that can be properly analyzed.

![image](/assets/img/ios-pentesting/Part-II/hopper-decrypted-content.png)

## Setup BurpSuite
