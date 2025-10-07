---
date: 2025-10-07 20:02:15
layout: post
title: iOS All The Things - Part IV

description: 
image: /assets/img/ios-pentesting/Part-IV/cover4.jpeg
optimized_image: /assets/img/ios-pentesting/Part-IV/cover4.jpeg
category: blog
tags:
  - iOS Pentesting
  - IOS Penetration Testing
  - Code Obfuscation
  - iOS code security
  - Third Party Libraries
  - deeplinks
  - url schema
  - IPC
---

# Agenda of iOS Pentesting:
1. [Intro](#intro)
2. [iOS Code Security](#ios-code-security)
3. [Third Party Libraries](#third-party-libraries)
4. [Inter-Process Communication (IPC)](#inter-process-communication-ipc)
5. [iOS App Attack Surface](#ios-app-attack-surface)
6. [Conclusion](#conclusion)

## Intro

Our journey is nearing its end, In this part, we move beyond the standard techniques to tackle the sophisticated security challenges that define modern iOS applications.

we're going to explore those advanced areas. We'll look at how developers try to protect their code from people like us, why the external libraries an app uses can be a major weak spot, how apps communicate with each other (and how we can listen in), and finally, how to map out every single place an attacker could possibly target.

This is where we transition from performing basic tests to conducting comprehensive security assessments that uncover deep, systemic vulnerabilities. Let's complete our mission.

## iOS Code Security

iOS code security encompasses the techniques and mechanisms used to protect an application's code from unauthorized analysis, reverse engineering, and tampering. For penetration testers, understanding these protections is crucial because they represent the first line of defense we must bypass to assess the application's true security.

**Key Areas of iOS Code Security:**

a. Code Obfuscation: make the code difficult for humans to read and understand.

  * Common Techniques:
    * Mangling: Changing meaningful class and method names to random characters (talks in Part-III).
    * Control Flow Flattening: Transforming straightforward code logic into complex, hard-to-follow structures.
    * String Encryption: Encrypting hardcoded strings and decrypting them only at runtime.
    * Instruction Substitution: Replacing simple instructions with more complex equivalent operations.

   > **Important Tip:** Objective-c is easier to reverse using ghidra.

  Example on Obfuscation:
  
  The standard compiler generates binary symbols based on class and function names from the source code. Therefore, if no obfuscation was applied, symbol names remain meaningful and can be easily read straight from the app binary. For instance, a function which detects a jailbreak can be located by searching for relevant keywords (e.g. "jailbreak"). The listing below shows the disassembled function `JailbreakDetectionViewController.jailbreakTest4Tapped` from the DVIA-v2 app.

```assembly
  __T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF:
  stp        x22, x21, [sp, #-0x30]! 
  mov        rbp, rsp
```

  After the obfuscation we can observe that the symbol's name is no longer meaningful as shown on the listing below.

```assembly
  __T07DVIA_v232zNNtWKQptikYUBNBgfFVMjSkvRdhhnbyyFySbyypF:
  stp        x22, x21, [sp, #-0x30]!
  mov        rbp, rsp
```

  Nevertheless, this only applies to the names of functions, classes and fields. The actual code remains unmodified, so an attacker can still read the disassembled version of the function and try to understand its purpose (e.g. to retrieve the logic of a security algorithm).

  **SwiftShield:** Developers can use third-party tools like [Swiftshield](https://github.com/rockbruno/swiftshield) to automatically obfuscate their code, making it much harder for attackers to read and understand. This is a commercial product designed specifically to protect iOS applications.

  It is now detecting class and method names and is replacing their identifier with an encrypted value.

  In the original source code you can see all the class and method identifiers:

  ![image](/assets/img/ios-pentesting/Part-IV/source-code-decrypt.png)

  SwiftShield was now replacing all of them with encrypted values that leave no trace to their original name or intention of the class/method:

  ![image](/assets/img/ios-pentesting/Part-IV/code-encrypt.png)

  After executing `swiftshield` a new directory will be created called `swiftshield-output`. In this directory another directory is created with a timestamp in the folder name. This directory contains a text file called `conversionMap.txt`, that maps the encrypted strings to their original values.

  ```bash
  $ cat conversionMap.txt
  //
  // SwiftShield Conversion Map
  // Automatic mode for SwiftSecurity, 2020-01-02 13.51.03
  // Deobfuscate crash logs (or any text file) by running:
  // swiftshield -deobfuscate CRASH_FILE -deobfuscate_map THIS_FILE
  //

  ViewController ===> hTOUoUmUcEZUqhVHRrjrMUnYqbdqWByU
  viewDidLoad ===> DLaNRaFbfmdTDuJCPFXrGhsWhoQyKLnO
  sceneDidBecomeActive ===> SUANAnWpkyaIWlGUqwXitCoQSYeVilGe
  AppDelegate ===> KftEWsJcctNEmGuvwZGPbusIxEFOVcIb
  Deny_Debugger ===> lKEITOpOvLWCFgSCKZdUtpuqiwlvxSjx
  Button_Emulator ===> akcVscrZFdBBYqYrcmhhyXAevNdXOKeG
  ```

  
