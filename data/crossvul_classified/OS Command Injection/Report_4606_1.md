# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4606_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4606_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

var fs = require('fs')
var path = require('path')
var request = require('teeny-request').teenyRequest
var urlgrey = require('urlgrey')
var jsYaml = require('js-yaml')
var walk = require('ignore-walk')
var execSync = require('child_process').execSync
var validator = require('validator')

var detectProvider = require('./detect')

var version = 'v' + require('../package.json').version

var patterns,
  more_patterns = ''

var isWindows =
  process.platform.match(/win32/) || process.platform.match(/win64/)

if (!isWindows) {
  patterns =
    "-type f \\( -name '*coverage.*' " +
    "-or -name 'nosetests.xml' " +
    "-or -name 'jacoco*.xml' " +
    "-or -name 'clover.xml' " +
    "-or -name 'report.xml' " +
    "-or -name 'cobertura.xml' " +
    "-or -name 'luacov.report.out' " +
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,6 @@
 var jsYaml = require('js-yaml')
 var walk = require('ignore-walk')
 var execSync = require('child_process').execSync
-var validator = require('validator')
 
 var detectProvider = require('./detect')
 
@@ -394,13 +393,13 @@
       if (!isWindows) {
         gcov =
           'find ' +
-          (args.options['gcov-root'] || root) +
+          (sanitizeVar(args.options['gcov-root']) || root) +
           " -type f -name '*.gcno' " +
           gcg +
           ' -exec ' +
-          (validator.escape(args.options['gcov-exec']) || 'gcov') +
+          (sanitizeVar(args.options['gcov-exec']) || 'gcov') +
           ' ' +
-          (validator.escape(args.options['gcov-args']) || '') +
+          (sanitizeVar(args.options['gcov-args']) || '') +
           ' {} +'
       } else {
         // @TODO support for root
@@ -409,9 +408,9 @@
           'for /f "delims=" %g in (\'dir /a-d /b /s *.gcno ' +
           gcg +
           "') do " +
-          (args.options['gcov-exec'] || 'gcov') +
+          (sanitizeVar(args.options['gcov-exec']) || 'gcov') +
           ' ' +
-          (args.options['gcov-args'] || '') +
+          (sanitizeVar(args.options['gcov-args']) || '') +
           ' %g'
       }
       debug.push(gcov)
@@ -556,7 +555,12 @@
   }
 }
 
+function sanitizeVar(arg) {
+  return arg.replace(/&/g, '')
+}
+
 module.exports = {
+  sanitizeVar: sanitizeVar,
   upload: upload,
   version: version,
   sendToCodecovV2: sendToCodecovV2,
```
