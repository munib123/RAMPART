# CrossVul Fix Pair: Improper Control of Dynamically-Managed Code Resources in javascript
**Pair ID:** 1976_1
**Vulnerability Class:** Improper Control of Dynamically-Managed Code Resources
**CWE:** CWE-913
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1976_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Dynamically-Managed Code Resources - Many languages offer powerful features that allow the programmer to dynamically create or modify existing code, or resources used by code such as variables and objects.

## Vulnerable Code
```javascript
Lines 1-22 of the vulnerable file.

var readline = require('readline');

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

module.exports = cliMain;

var instance = require('../lib/index.js');

var commands = {
  'get': cmdGet,
  'set': cmdSet,
  'remove': cmdRemove,
  'keys': cmdKeys,
  'save': cmdSave,
  'load': cmdLoad,
  'convert': cmdConvert,
  'dropBackup': cmdDropBackup,
  'help': cmdHelp,
  'exit': cmdExit
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 var readline = require('readline');
+var JSON5 = require('json5');
 
 var rl = readline.createInterface({
   input: process.stdin,
@@ -77,7 +78,7 @@
   try {
     var strTest = /^[\'\"](.*?)[\'\"]$/.exec(val);
     if (!strTest || strTest.length !== 2) { // do not parse if explicitly a string
-      objVal = eval('(' + val + ')'); // attempt to parse
+      objVal = JSON5.parse(val); // attempt to parse
     } else {
       objVal = strTest[1];
     }
```
