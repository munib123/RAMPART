# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 4073_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4073_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

/* Pi-hole: A black hole for Internet advertisements
 *  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
 *  Network-wide ad blocking via your own hardware.
 *
 *  This file is copyright under the latest version of the EUPL.
 *  Please see LICENSE file for your rights under this license. */

var table;
var token = $("#token").text();

function showAlert(type, message) {
  var alertElement = null;
  var messageElement = null;

  switch (type) {
    case "info":
      alertElement = $("#alInfo");
      break;
    case "success":
      alertElement = $("#alSuccess");
      break;
    case "warning":
      alertElement = $("#alWarning");
      messageElement = $("#warn");
      break;
    case "error":
      alertElement = $("#alFailure");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,8 @@
  *
  *  This file is copyright under the latest version of the EUPL.
  *  Please see LICENSE file for your rights under this license. */
+
+/* global utils:false */
 
 var table;
 var token = $("#token").text();
@@ -76,8 +78,8 @@
 });
 
 function addCustomDNS() {
-  var ip = $("#ip").val();
-  var domain = $("#domain").val();
+  var ip = utils.escapeHtml($("#ip").val());
+  var domain = utils.escapeHtml($("#domain").val());
 
   showAlert("info");
   $.ajax({
```
