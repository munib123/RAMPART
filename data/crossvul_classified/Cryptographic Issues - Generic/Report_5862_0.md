# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 5862_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5862_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2012 Joel Martin
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 */

"use strict";
/*jslint bitwise: false, white: false */
/*global Util, window, document */

// Globals defined here
var WebUtil = {}, $D;

/*
 * Simple DOM selector by ID
 */
if (!window.$D) {
    window.$D = function (id) {
        if (document.getElementById) {
            return document.getElementById(id);
        } else if (document.all) {
            return document.all[id];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 /*
  * noVNC: HTML5 VNC client
  * Copyright (C) 2012 Joel Martin
+ * Copyright (C) 2013 NTT corp.
  * Licensed under MPL 2.0 (see LICENSE.txt)
  *
  * See README.md for usage and integration instructions.
@@ -94,16 +95,20 @@
 
 // No days means only for this browser session
 WebUtil.createCookie = function(name,value,days) {
-    var date, expires;
+    var date, expires, secure;
     if (days) {
         date = new Date();
         date.setTime(date.getTime()+(days*24*60*60*1000));
         expires = "; expires="+date.toGMTString();
-    }
-    else {
+    } else {
         expires = "";
     }
-    document.cookie = name+"="+value+expires+"; path=/";
+    if (document.location.protocol === "https:") {
+        secure = "; secure";
+    } else {
+        secure = "";
+    }
+    document.cookie = name+"="+value+expires+"; path=/"+secure;
 };
 
 WebUtil.readCookie = function(name, defaultValue) {
```
