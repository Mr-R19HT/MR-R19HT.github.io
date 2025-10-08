---
date: 2025-10-08 00:02:15
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

a. **Code Obfuscation:** make the code difficult for humans to read and understand.

  * Common Techniques:
    * Mangling: Changing meaningful class and method names to random characters (talks in Part-III).
    * Control Flow Flattening: Transforming straightforward code logic into complex, hard-to-follow structures.
    * String Encryption: Encrypting hardcoded strings and decrypting them only at runtime.
    * Instruction Substitution: Replacing simple instructions with more complex equivalent operations.

   > **Note:** Objective-c is easier to reverse using ghidra.

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

  **Hardcoded Secrets**
  
  Without proper obfuscation, hardcoded secrets become low-hanging fruit for attackers. When code isn't obfuscated, sensitive information remains in plain sight within the binary, making it easily discoverable through basic reverse engineering techniques.

  In files or Decompiled source code:
  
  * Analyze the strings within the binary for any signs of sensitive data, such as API keys, tokens, credentials, or URLs.
  * Search through the codebase for hardcoded values that may indicate secrets. Look for keywords such as: _API_KEY_, _ACCESS_TOKEN_, _SECRET_, _PASSWORD_, _PASSWD_, _AUTH_, _KEY_, _TOKEN_, _PRIVATE_KEY_, _CLIENT_ID_, _CLIENT_SECRET_, _USERNAME_, _DB_PASSWORD._
  * Review configuration files and other resources within the app for any embedded sensitive information.

  Using simple command `strings` to get sensitive data:

  ```bash
  strings DVIA-v2

  # specify hardcoded secrets we want to search
  strings DVIA-v2 | grep -i "api\|key\|token\|password\|secret"
  ```

  ![image](/assets/img/ios-pentesting/Part-IV/strings.png)

  or can search on decompiled source code by ghidra

  ![image](/assets/img/ios-pentesting/Part-IV/ghidra.png)


b. **Anti-Debugging Protections:** Prevent attackers from debugging the application.

  * Common Implementations:
    * `ptrace` system call with `PT_DENY_ATTACH` flag.
    * `sysctl` to check for debugger presence.
    * `getppid()` to detect if the process is being debugged.
    * Signal handlers to detect breakpoints.

c. **Anti-Tampering Mechanisms**: Detect if the application has been modified.

  * Common Approaches:
    * Integrity Checks: Calculating and verifying checksums of the application binary.
    * Signature Verification: Checking the code signature at runtime.
    * Jailbreak Detection: Identifying if the device is jailbroken.

d. **Runtime Protection:** Protect the application while it's running.

   * Techniques Include:
     * Method Swizzling Detection: Monitoring for attempts to hook Objective-C methods.
     * Frida Detection: Checking for Frida's presence in memory.
     * SSL Pinning: Preventing traffic interception.

e. **Debugging Symbols**: are crucial metadata generated during the compilation process that map the compiled binary code back to the original source code. They play a significant role in both development and security analysis.

  * makes reverse engineering easier.
  * symbol table of mach-o binary.
  * check with tools like: objdump, llvm-objdump, nm.
  * get-task-allow entitlement.

  > **Note:** Xcode automatically adds the `Get Task Allow` entitlement to apps that you build for debugging, while removing the entitlement before App Store submission. This enables Xcode itself to attach to and debug your app during development.

  On Linux to check the debugging symbols enabled or not:

  ```bash
  sudo apt-get install llvm
  llvm-objdump --syms DVIA-v2 | grep "      d"
  ```

  ![image](/assets/img/ios-pentesting/Part-IV/llvm.png)

  ```bash
  # or can use that
  ipsw ent --input DVIA-v2
  ```  

  ![image](/assets/img/ios-pentesting/Part-IV/ipsw.png)

  That output means debugging symbols is enabled.

### Testing Methodology

a. **Static Analysis:**

  * Use tools like strings to look for protection indicators.
  * Search for common anti-debugging function names.
  * Analyze the binary for unusual code patterns.

b. **Dynamic Analysis:**

  * Run the app and monitor for crash or exit when debugging tools are attached.
  * Use Frida to hook security-related functions.
  * Test the application's behavior in jailed vs jailbroken environments.

c. **Bypass Techniques:**

  * Patch anti-debugging checks using Frida or binary patching.
  * Use runtime manipulation to override protection logic.
  * Employ kernel-level bypasses for advanced protections.

### Common Vulnerabilities in Code Security

* **Inconsistent Protection:** Some parts of the app are protected while others are not.
* **Client-Side Only Checks:** Protection logic that can be easily bypassed.
* **Predictable Obfuscation:** Patterns that can be recognized and reversed.
* **Error Handling:** Protections that crash the app rather than failing gracefully.

## Third Party Libraries

Third-party libraries are pre-built code components that developers integrate into their iOS apps to add functionality without building everything from scratch. While they save development time, they introduce significant security risks that penetration testers must assess.

**Here's what penetration testers need to know:**

a. Insecure Dependencies

  * The Dependency Chain Problem:
    * Libraries often depend on other libraries.
    * Vulnerabilities can hide deep in the dependency tree.
    * Developers may be unaware of all components in their app.

    Common Issues:

    ```bash
    # Example: Checking for vulnerable Alamofire version
    # CVE-2023-XXXX - SSL bypass vulnerability in Alamofire < 5.6.0
    strings Binary-App | grep Alamofire

    # Using MobSF to scan for known vulnerabilities
    python3 mobsf_analyzer.py -i App.ipa
    ```

    Detection Methods:

    ```bash
    # Check Podfile.lock for dependency versions
    cat Podfile.lock | grep -A 5 "DEPENDENCIES"

    # Manual version checking for common libraries
    strings Binary-App | grep -E "[0-9]+\.[0-9]+\.[0-9]+"
    ```

b. Dylib Risks

  * Dynamic libraries loaded at runtime.
  * Can be swapped or injected with malicious versions.
  * Common in plugin architectures and modular apps.

  Security Concerns:

  ```bash
  # Check for embedded dylibs
  find YourApp.app -name "*.dylib"

  # Check rpath for insecure paths
  strings Binary-App | grep -A 3 LC_RPATH
  ```

  We can use objection to get dynamic library loads and frameworks:

  ```bash
  ios bundles list_bundles
  ios bundles list_frameworks
  ```

  ![image](/assets/img/ios-pentesting/Part-IV/objection.png)

  We can use ipsw to get dynamic library loads and frameworks:

  ```bash
  ipsw macho info DVIA-v2
  ```

   ![image](/assets/img/ios-pentesting/Part-IV/libs-frames.png)

   We can use frida script to monitor dylib loading:

   ```javascript
  Interceptor.attach(Module.findExportByName(null, "dlopen"), {
      onEnter: function(args) {
          var path = args[0].readCString();
          console.log("[+] Loading dylib: " + path);
          // Flag suspicious paths outside app bundle
          if (path && !path.includes("/var/containers/Bundle/Application/")) {
              console.log("[!] Suspicious dylib path: " + path);
          }
      }
  });
   ```



    

