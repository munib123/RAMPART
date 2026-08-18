# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 708_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `708_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 1-25 of the vulnerable file.

"use strict";

var exec = require("child_process").exec;
var fs = require("fs");
var flag = process.argv[2] || "--exists";

// Normally |pkg-config opencv ...| could report either OpenCV 2.x or OpenCV 3.y
// depending on what is installed.  To enable both 2.x and 3.y to co-exist on
// the same machine, the opencv.pc for 3.y can be installed as opencv3.pc and
// then selected by |export PKG_CONFIG_OPENCV3=1| before building node-opencv.
var opencv = process.env.PKG_CONFIG_OPENCV3 === "1" ? "opencv3" : '"opencv >= 2.3.1"';

function main(){
    //Try using pkg-config, but if it fails and it is on Windows, try the fallback
    exec("pkg-config " + opencv + " " + flag, function(error, stdout, stderr){
        if(error){
            if(process.platform === "win32"){
                fallback();
            }
            else{
                throw new Error("ERROR: failed to run: pkg-config", opencv, flag);
            }
        }
        else{
            console.log(stdout);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,13 +2,13 @@
 
 var exec = require("child_process").exec;
 var fs = require("fs");
-var flag = process.argv[2] || "--exists";
+var flag = "--exists";
 
 // Normally |pkg-config opencv ...| could report either OpenCV 2.x or OpenCV 3.y
 // depending on what is installed.  To enable both 2.x and 3.y to co-exist on
 // the same machine, the opencv.pc for 3.y can be installed as opencv3.pc and
 // then selected by |export PKG_CONFIG_OPENCV3=1| before building node-opencv.
-var opencv = process.env.PKG_CONFIG_OPENCV3 === "1" ? "opencv3" : '"opencv >= 2.3.1"';
+var opencv = process.env.PKG_CONFIG_OPENCV3 === "1" ? "opencv3" : ' "opencv >= 2.3.1"';
 
 function main(){
     //Try using pkg-config, but if it fails and it is on Windows, try the fallback
@@ -18,7 +18,7 @@
                 fallback();
             }
             else{
-                throw new Error("ERROR: failed to run: pkg-config", opencv, flag);
+              throw new Error("ERROR: failed to run: pkg-config" + opencv + " " + flag + " - Is OpenCV installed?");
             }
         }
         else{
```
