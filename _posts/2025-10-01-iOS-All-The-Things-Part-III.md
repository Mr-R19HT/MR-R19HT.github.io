---
date: 2025-10-01 02:58:15
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
# -U: Connect to a USB device
# -f: Spawn the app with this package name
# -n: Attach to the process with this name

frida -U -f com.highaltitudehacks.DVIAswiftv2 -n 'DVIA-v2'
```

**Here are fundamental commands:**

![image](/assets/img/ios-pentesting/Part-III/objc-frida.png)

* `ObjC.available`: This is a crucial check you should perform at the beginning of your scripts. It returns true if the Objective-C runtime is accessible within the target process, and false if it is not. This confirms you are in the right context before trying to execute any other Objective-C commands.

* `ObjC.classes`: This command provides a goldmine of information. It returns a list of all Objective-C classes currently loaded in the application's memory. This is your starting point for understanding the app's structure and finding interesting targets to hook and manipulate.

* another commands:
  
  * `frida-trace`: is a dynamic tracing tool built on top of Frida that automatically instruments and traces function calls in applications. It's designed for quick and easy function monitoring without writing custom scripts.

  ![image](/assets/img/ios-pentesting/Part-III/classes-frida.png)

  ![image](/assets/img/ios-pentesting/Part-III/methods-frida-trace.png)

```bash
# -U: Connect to a USB device
# -f: Spawn the app with this package name
# -i: Trace functions containing "jailbreak" in their name
    
frida-trace -U -f com.highaltitudehacks.DVIAswiftv2 -i "*jailbreak*"

# -m: To get all specific method
# *: Enable pattern matching for function names
# -n: Attach to the process with this name

frida-trace -U -n "DVIA-v2" -m "*[jailbreak* *]"
```

  *  `frida-discover`:  is a specialized tool in the Frida suite designed for automated function discovery in binaries and applications. It helps you find interesting functions to trace or hook when you don't know what you're looking for.

```bash
# discover all classes and methods of the app
# -U: Connect to a USB device
# -n: Attach to the process with this name

frida-discover -U -n "DVIA-v2"
```
    
**Example: Using Frida Scripts to bypass Jailbreak**

a. Get all classes of app

  ![image](/assets/img/ios-pentesting/Part-III/view-classes-frida.png)

  ```javascript
// Iterate through all available Objective-C classes in the runtime
// This loop goes through every class that Frida can discover in the Objective-C runtime
for (var className in ObjC.classes) {
    
    // Safety check: Verify that the property actually belongs to ObjC.classes object
    // This prevents iterating over inherited properties from the prototype chain
    if (ObjC.classes.hasOwnProperty(className)) {
        
        // Print the class name to the console
        // This reveals all Objective-C classes currently loaded in the target application
        console.log(className);
    }
}
  ```
  
  ```bash
# run the script on the app to see all classes
frida -U -l viewclasses.js DIVA-V2
  ```

b. Get all methods of specific class like "JailbreakDetection"

  ```javascript
// Log startup message to indicate script execution has begun
console.log("[*] Started: Find All Methods of a Specific Class");

// Check if Objective-C runtime is available in the current context
// This is important because this script only works on iOS/macOS apps
if (ObjC.available) {
    try {
        // Define the target class name we want to inspect
        // This should be replaced with the actual class you're investigating
        var className = "JailbreakDetection";
        
        // Access all methods of the specified class
        // The $methods property contains an array of all instance and class methods
        var methods = ObjC.classes[className].$methods;  
        
        // Iterate through each method in the class
        for (var i = 0; i < methods.length; i++) {
            try { 
                // Print each method name with a prefix for visibility
                // This reveals all available methods in the JailbreakDetection class
                console.log("[-] " + methods[i]);  
            } catch(err) { 
                // Handle exceptions for individual method access
                // This prevents one faulty method from breaking the entire loop
                console.log("[1] Exception1: " + err.message); 
            }
        }
    } catch(err) { 
        // Handle exceptions for class-level access failures
        // This occurs if the class doesn't exist or can't be accessed
        console.log("[1] Exception2: " + err.message); 
    }    
} else { 
    // This branch executes if the script runs in a non-Objective-C environment
    // (e.g., Android, Windows, or non-instrumented process)
    console.log("Objective-C Runtime is not available!"); 
}

// Log completion message to indicate script has finished execution
console.log("[*] Completed: Find All Methods of a Specific Class");
  ```

c. Grep on the specific method

  ![image](/assets/img/ios-pentesting/Part-III/method-frida-script.png)


  ```bash
  frida -U -l viewmethods.js DIVA-V2 | grep -i 'jailbreak\|jailbroken'
  ```

d. Get the original return value

e. overwrite on the return value to bypass it
