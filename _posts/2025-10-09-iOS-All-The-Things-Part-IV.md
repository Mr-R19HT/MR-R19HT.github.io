---
date: 2025-10-09 18:26:15
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
5. [Web Views Javascript to Native Bridge](#web-views-javascript-to-native-bridge)
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

**Testing Methodology**

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

**Common Vulnerabilities in Code Security**

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
  // Real-time interception of library loading
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
  
c. Library Permissions Analysis

  * Libraries often request more permissions than needed
  * Can lead to data leakage or privilege escalation

  Checking Library Permissions:
  
  ```bash
  # run command on ios jailbroken device
  # Extract entitlements from the app
  ldid -e "Binary-App" > app_entitlements.plist

  # Check embedded framework entitlements
  ldid -e App/Frameworks/Analytics.framework > analytics_entitlements.plist
  ```

  Common Over-Privileged Libraries:

  ```xml
  <!-- Example of excessive entitlements in library -->
  <key>com.apple.developer.associated-domains</key>
  <array>
      <string>applinks:example.com</string>
      <string>applinks:tracking-library.com</string> <!-- Suspicious -->
  </array>
  <key>com.apple.developer.networking.wifi-info</key> <!-- Often unnecessary -->
  <true/>
  ```

**Testing Methodology:**

  * Dependency Vulnerability Assessment:

    ```bash
    # Automated vulnerability scanning
    dependency-check --project "App" --scan "Podfile.lock"

    # Manual version verification
    grep -A 10 "Alamofire" Podfile.lock
    grep -A 10 "Firebase" Podfile.lock
    ```

  * Dylib Security Analysis:

    ```javascript
    // Snapshot of currently loaded librarie
    Process.enumerateModules({
      onMatch: function(module){
          if (module.path.includes(".dylib")) {
              console.log("Loaded Dylib: " + module.name + " at " + module.path);
          }
      },
      onComplete: function(){}
    });
    ```

  * Permission Audit:

    ```bash
    # Compare app vs library entitlements
    diff app_entitlements.plist analytics_entitlements.plist
    ```

**Remediation Recommendations**

* For Developers:
    * Regular Dependency Updates.
    * Dylib Security:
        * Use @loader_path instead of @executable_path.
        * Validate dylib code signatures at runtime.
        * Restrict dylib loading to app bundle only.
    * Permission Minimization:
        * Review each library's entitlement requests.
        * Remove unnecessary permissions.
        * Use app groups selectively.

* For Penetration Testers:
    * Always include dependency vulnerability scanning.
    * Verify dylib loading paths and signatures.
    * Audit library permissions against functionality.
    * Test for runtime library manipulation.

> **Important Link:** special for [Dylib](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-dyld-hijacking-and-dyld_insert_libraries.html)

## Inter-Process Communication (IPC)

Inter-Process Communication (IPC) allows iOS applications to exchange data and communicate with other apps, extensions, and system services. While IPC enables powerful functionality, it also creates significant security risks that penetration testers must evaluate.

**Types of IPC Mechanisms in iOS:**

a. URL Schemes:
  
  * Allow apps to communicate via custom URLs.
  * Can be exploited for unauthorized data access or actions.
  * How They Work:
    * Apps register a custom URL scheme (e.g., `myapp://`) in their `Info.plist`:

    ```xml
       <key>CFBundleURLTypes</key>
       <array>
          <dict>
              <key>CFBundleURLSchemes</key>
               <array>
                  <string>myapp</string>
               </array>
          </dict>
       </array>
     ```
    
    * When a user clicks a link like `myapp://profile/123`, iOS checks if any app has registered `myapp://` and opens it.  

b. Universal Links:

  * A deeplink in mobile application is like a special link that takes you directly to a specific part of a mobile app instead of a website. This means you can easily switch between apps or go from a website to an app without having to click a lot of buttons. It makes it quicker and easier to find what you’re looking for in the app.
  * Can be hijacked if not properly validated.
  * How They Work:
      * Uses standard HTTPS links (e.g., `https://example.com/profile/123`) instead of custom schemes.
      * Server Setup: Host an `apple-app-site-association` (AASA) JSON file at `https://example.com/.well-known/apple-app-site-association`.

        ```json
         {
           "applinks": {
               "apps": [],
                 "details": [
                       {
                           "appID": "TEAMID.com.example.app",
                           "paths": ["/profile/*", "/settings"]
                       }
                 ]  
             }
         }
        ```
        
      * App Setup: Enable "Associated Domains" in Xcode and add
   
        ```text
             applinks:example.com
        ```

        **URL Schemes vs Universal Links:**
        
        | Feature             | URL Schemes (`myapp://`)    | Universal Links (`https://`) |
        | ------------------- | ----------------------------| -----------------------------|
        | **Security**        | No ownership check          | Verified via AASA file     |
        | **User Experience** | Shows "Open in App?" prompt | Opens silently             |
        | **Fallback**        | Fails if app not installed  | Opens in Safari            |
        | **Implementation**  | Just `Info.plist`           | Needs server config        |
        | **iOS Support**     | All versions                | iOS 9+                     |
        | **Phishing Risk**   | High (hijackable)           | Low (secure)               |

        **How to test url schemes and universal links**
        
        * Get all url schemes and universal links.

          ```bash
          # go to file and search on "CFBundleURLTypes" or "LSApplicationQueriesSchemes" to get url schemes
          ipsw plist info.plist > info.plist.json

          # search on "com.apple.developer.associated-domain" to get universal links
          ipsw macho info Binary-App
          ```
   
          ![image](/assets/img/ios-pentesting/Part-IV/url-schemes.png)
   
          ![image](/assets/img/ios-pentesting/Part-IV/universal-links.png) 
 
        * Another way to get all links.

          ```bash
          strings Binary-App | grep "://"
          ```
   
          ![image](/assets/img/ios-pentesting/Part-IV/links.png) 
       
        * Use uiopen on ios jailbroken device to check links.

          ```bash
          # Test Url Schemes Handling
          uiopen "myapp://profile/123"

          # Check for sensitive data exposure
          uiopen "myapp://get-token"
          uiopen "myapp://export-database"
          ```
       
        * We can use Frida instead of uiopen to do same thing:
            * To intercept openurl function
              
             ```javascript
             function openURL(url) {
              var UIApplication = ObjC.classes.UIApplication.sharedApplication();
              var nsURL = ObjC.classes.NSURL.URLWithString_(url);
              return UIApplication.openURL_(nsURL);
             }
             ```
            * Request the url schemas
         
            ![image](/assets/img/ios-pentesting/Part-IV/openurl.png) 


            * Can use frida-trace to get the methods and classes that using openurl, run it then go to ssh connection on device and run the url schema using uiopen to trace exactly what is method and class use that url schema.

              ```bash
              frida-trace -U -m '*[* *openURL*]' -p 1234
              ```
       
              ![image](/assets/img/ios-pentesting/Part-IV/trace.png)
              
c. Keychain Sharing:

  * The iOS Keychain is a secure storage system for sensitive information like passwords, credit card details, and cryptographic keys, accessible to apps and the user.
  * Allows apps from same developer to share sensitive data.
  * Implemented through Keychain Access Groups.

    ![image](/assets/img/ios-pentesting/Part-IV/keychain.png)
    
  * Keychain Data Protection Classes

    ![image](/assets/img/ios-pentesting/Part-IV/keychain-classes.png)
  
  * To know the ios app use keychain or not, check keychain api includes the following main operations:
      * secitemadd
      * secitemupdate
      * secitemdelete
      * secitemdelete

     ```bash
     strings Binary-app | grep "SecItem"
     ```

     ![image](/assets/img/ios-pentesting/Part-IV/ops-keychain.png)

  * Keychain data extraction

    ```bash
    // Using Objection to dump keychain
    ios keychain dump

    // Using Frida for keychain analysis
    ObjC.classes.SecItem.copyMatching.implementation = function(query) {
    console.log("[+] Keychain query: " + query);
    return this.self.copyMatching(query);
    };
    ```

d. XPC Services:

  * Lightweight inter-process communication.
  * Used for app-to-app and app-to-system service communication.

e. App Extensions:
  
  * Today Widgets, Share Extensions, Action Extensions.
  * Run in separate processes but share data with host app.

f. UIActivityViewController:

  * Shares data between apps through system-provided activities.
  * Can leak sensitive information to unauthorized apps.

g. App Groups:

  * Allows multiple apps or extensions to share container storage.
  * Uses shared file containers for data exchange.

**Common IPC Vulnerabilities:**

a. URL Scheme Hijacking:

  * Unprotected URL schemes allowing any app to trigger actions.
  * Lack of input validation in URL parameters.
  * Sensitive data exposure through callback URLs.

b. Insecure App Group Sharing:

  * World-readable shared containers.
  * Lack of encryption in shared files.
  * Improper access controls.

c. Keychain Access Issues:

  * Overly permissive keychain access groups.
  * Weak keychain item protection classes.
  * Failure to use appropriate accessibility settings.

d. Extension Vulnerabilities:

  * Extensions with excessive permissions.
  * Data leakage between host app and extension.
  * Inadequate sandboxing.

**Security Best Practices**

a. URL Scheme Protection:

  * Validate incoming URL parameters.
  * Implement custom URL scheme authentication.
  * Restrict sensitive actions to authenticated users.

b. App Group Security:

  * Encrypt sensitive data in shared containers.
  * Implement proper file permissions.
  * Use separate app groups for different sensitivity levels.

c. Keychain Hardening:

  * Use appropriate protection classes (kSecAttrAccessibleWhenUnlocked).
  * Implement proper access control settings.
  * Regularly audit keychain usage.

d. Extension Security:

  * Minimize extension permissions.
  * Implement data sanitization.
  * Use separate app groups for sensitive data.

## Web Views Javascript to Native Bridge

The WebView JavaScript to Native bridge allows communication between web content loaded in a WebView and the native iOS application. While powerful for hybrid apps, this bridge introduces significant security risks if not properly implemented.

**Types of Webviews:**

a. UIWebView: is deprecated starting on iOS 12 and should not be used. Make sure that either `WKWebView` or `SFSafariViewController` are used to embed web content. In addition to that, JavaScript cannot be disabled for `UIWebView` which is another reason to refrain from using it.

b. WKWebView: was introduced with iOS 8 and is the appropriate choice for extending app functionality, controlling displayed content (i.e., prevent the user from navigating to arbitrary URLs) and customizing.

  * `WKWebView` comes with several security advantages over `UIWebView`:
    * JavaScript is enabled by default but thanks to the `javaScriptEnabled` property of `WKWebView`, it can be completely disabled, preventing all script injection flaws.
    * The `JavaScriptCanOpenWindowsAutomatically` can be used to prevent JavaScript from opening new windows, such as pop-ups.
    * The `hasOnlySecureContent` property can be used to verify resources loaded by the WebView are retrieved through encrypted connections.
    * `WKWebView` implements out-of-process rendering, so memory corruption bugs won't affect the main app process.

    > **Tip:** A JavaScript Bridge can be enabled when using `WKWebView` and `UIWebView` 

c. SFSafariViewController: is available starting on iOS 9 and should be used to provide a generalized web viewing experience. These WebViews can be easily spotted as they have a characteristic layout which includes the following elements:

  * A read-only address field with a security indicator.
  * An Action ("Share") button.
  * A Done button, back and forward navigation buttons, and a "Safari" button to open the page directly in Safari.

    ![image](/assets/img/ios-pentesting/Part-IV/safari.png)

  * There are a couple of things to consider:
    * JavaScript cannot be disabled in `SFSafariViewController` and this is one of the reasons why the usage of `WKWebView` is recommended when the goal is extending the app's user interface.
    * `SFSafariViewController` also shares cookies and other website data with Safari.
    * The user's activity and interaction with a `SFSafariViewController` are not visible to the app, which cannot access AutoFill data, browsing history, or website data.
    * According to the App Store Review Guidelines, `SFSafariViewController`s may not be hidden or obscured by other views or layers.

**Check vulnerable and deprecated Components:**
   
If you have access to the source code, you can check for the use of UIWebView, which Apple has deprecated due to known security vulnerabilities and performance issues. 

 ![image](/assets/img/ios-pentesting/Part-IV/uiwebview.png)

If you don't have the source code, you can still check if the app uses UIWebView by running a simple command on the binary.

 ![image](/assets/img/ios-pentesting/Part-IV/uiwebview-tool.png)

**Javascript Bridges**

From iOS 7 onwards, Apple provided APIs for **communication between JavaScript in a WebView and native** Swift or Objective-C objects. This integration is primarily facilitated through two methods:

* **JSContext**: A JavaScript function is automatically created when a Swift or Objective-C block is linked to an identifier within a `JSContext`. This allows for seamless integration and communication between JavaScript and native code.
* **JSExport Protocol**: By inheriting the `JSExport` protocol, native properties, instance methods, and class methods can be exposed to JavaScript. This means any changes made in the JavaScript environment are mirrored in the native environment, and vice versa. However, it's essential to ensure that sensitive data is not exposed inadvertently through this method.

The procedure for exploiting the functions starts with producing a JavaScript payload and injecting it into the file that the app is requesting. The injection can be accomplished via various techniques, for example:

* If some of the content is loaded insecurely from the Internet over HTTP (mixed content), you can try to implement a MITM attack.
* You can always perform dynamic instrumentation and inject the JavaScript payload by using frameworks like Frida and the corresponding JavaScript evaluation functions available for the iOS WebViews (`stringByEvaluatingJavaScriptFromString:` for `UIWebView` and `evaluateJavaScript:completionHandler:` for `WKWebView`).

**Example on Web Views Javascript:**

In order to get the secret from the `Where's My Browser?` app, you can use one of these techniques to inject the following payload that will reveal the secret by writing it to the "result" field of the WebView:

```javascript
/**
 * JavaScript Bridge Callback Function
 * This function is called by native iOS code to return data to the web page
 * 
 * @param {string} name: The name/identifier of the callback or method being called
 * @param {string} value: The data/value returned from the native iOS side
 */
function javascriptBridgeCallBack(name, value) {
    // Update the HTML element with ID "result" to display the returned value
    // This is typically used to show the result of a native operation on the web page
    document.getElementById("result").innerHTML = value;
};

/**
 * Send a message from JavaScript to the native iOS WKWebView
 * This uses the WebKit message handler system to communicate with the iOS app
 */
window.webkit.messageHandlers.javaScriptBridge.postMessage(["getSecret"]);

// BREAKDOWN:
// window.webkit.messageHandlers: iOS WebKit's bridge for JavaScript-to-native communication
// .javaScriptBridge: The name of the message handler registered by the iOS app
// .postMessage(): Method to send data from JavaScript to native code
// ["getSecret"]: Array containing the command/message being sent to native code

/**
 * FLOW EXPLANATION:
 * 1. JavaScript sends "getSecret" command to iOS native code via postMessage()
 * 2. iOS app receives the message through WKScriptMessageHandler
 * 3. iOS processes the request (e.g., retrieves secret data)
 * 4. iOS calls back to JavaScript using javascriptBridgeCallBack() function
 * 5. The callback function updates the webpage with the result
 */
```

 ![image](/assets/img/ios-pentesting/Part-IV/webview-app.png)

## Conclusion

The pieces are now in place, and what a delightful set of toys we've assembled. Our exploration of iOS security has been like studying a worthy opponent's Nen abilities. understanding code protection, third-party dependencies, IPC, and WebView bridges has revealed the application's true potential for exploitation.

The magic lies not in individual techniques, but in how we combine them. Each vulnerability we've uncovered is like another playing card in our hand, waiting for the perfect moment to be deployed. The real performance begins in our next session, where we'll step into the arena of practical labs. I can already feel the excitement building. there's nothing quite like the thrill of testing one's skills against a properly challenging application.

Stay sharp, and keep your Nen ready. The most engaging battles and the most valuable discoveries, await us in the labs.

> **Quote from Hisoka:** A magician never reveals his secrets.
