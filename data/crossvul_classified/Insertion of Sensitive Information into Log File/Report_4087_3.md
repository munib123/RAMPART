# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in javascript
**Pair ID:** 4087_3
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4087_3`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

'use strict'
var npm = require('../npm.js')
var util = require('util')
var nameValidator = require('validate-npm-package-name')
var npmlog = require('npmlog')

module.exports = errorMessage

function errorMessage (er) {
  var short = []
  var detail = []
  switch (er.code) {
    case 'ENOAUDIT':
      short.push(['audit', er.message])
      break
    case 'EAUDITNOPJSON':
      short.push(['audit', er.message])
      break
    case 'EAUDITNOLOCK':
      short.push(['audit', er.message])
      detail.push(['audit', 'Try creating one first with: npm i --package-lock-only'])
      break

    case 'ECONNREFUSED':
      short.push(['', er])
      detail.push([
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,12 +3,17 @@
 var util = require('util')
 var nameValidator = require('validate-npm-package-name')
 var npmlog = require('npmlog')
+var replaceInfo = require('./replace-info.js')
 
 module.exports = errorMessage
 
 function errorMessage (er) {
   var short = []
   var detail = []
+
+  er.message = replaceInfo(er.message)
+  er.stack = replaceInfo(er.stack)
+
   switch (er.code) {
     case 'ENOAUDIT':
       short.push(['audit', er.message])
```
