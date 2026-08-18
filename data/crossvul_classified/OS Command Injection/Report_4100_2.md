# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4100_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4100_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

var fs = require('fs')
var path = require('path')
var request = require('teeny-request').teenyRequest
var urlgrey = require('urlgrey')
var jsYaml = require('js-yaml')
var walk = require('ignore-walk')
var execSync = require('child_process').execSync

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
@@ -4,21 +4,23 @@
 var urlgrey = require('urlgrey')
 var jsYaml = require('js-yaml')
 var walk = require('ignore-walk')
+var execFileSync = require('child_process').execFileSync
 var execSync = require('child_process').execSync
 
 var detectProvider = require('./detect')
 
 var version = 'v' + require('../package.json').version
 
-var patterns,
-  more_patterns = ''
+var patterns = ''
+var more_patterns = ''
+var winPatterns = ''
 
 var isWindows =
   process.platform.match(/win32/) || process.platform.match(/win64/)
 
 if (!isWindows) {
-  patterns =
-    "-type f \\( -name '*coverage.*' " +
+  patterns = (
+    "-type f -name '*coverage.*' " +
     "-or -name 'nosetests.xml' " +
     "-or -name 'jacoco*.xml' " +
     "-or -name 'clover.xml' " +
@@ -29,7 +31,7 @@
     "-or -name '*.lcov' " +
     "-or -name 'gcov.info' " +
     "-or -name '*.gcov' " +
-    "-or -name '*.lst' \\) " +
+    "-or -name '*.lst' " +
     "-not -name '*.sh' " +
     "-not -name '*.data' " +
     "-not -name '*.py' " +
@@ -76,9 +78,10 @@
     "-not -path '*/$bower_components/*' " +
     "-not -path '*/node_modules/*' " +
     "-not -path '*/conftest_*.c.gcov'"
+  ).split(' ')
 } else {
-  patterns =
-    '/a-d /b /s *coverage.* ' +
+  winPatterns = (
+    '/a:-d /b /s *coverage.* ' +
     '/s nosetests.xml ' +
     '/s jacoco*.xml ' +
     '/s clover.xml ' +
@@ -136,6 +139,7 @@
     '| findstr /i /v \\\\$bower_components\\ ' +
     '| findstr /i /v \\node_modules\\ ' +
     '| findstr /i /v \\conftest_.*\\.c\\.gcov '
+  ).split(' ')
 }
 
 var sendToCodecovV2 = function(
@@ -355,7 +359,7 @@
   console.log('==> Building file structure')
   try {
     upload +=
-      execSync('git ls-files || hg locate', { cwd: root })
+      execFileSync('git', ['ls-files', '||', 'hg', 'locate'], { cwd: root })
         .toString()
         .trim() + '\n<<<<<< network\n'
   } catch (err) {
@@ -414,7 +418,7 @@
       }
       debug.push(gcov)
       console.log('    $ ' + gcov)
-      execSync(gcov)
+      execFileSync(gcov)
     } catch (e) {
       console.log('    Failed to run gcov command.')
     }
@@ -431,19 +435,23 @@
       .toString()
       .trim()
   } else {
-    bowerrc = execSync('if exist .bowerrc type .bowerrc', { cwd: root })
-      .toString()
-      .trim()
+    bowerrc = fs.existsSync('.bowerrc')
   }
   if (bowerrc) {
     bowerrc = JSON.parse(bowerrc).directory
     if (bowerrc) {
       if (!isWindows) {
-        more_patterns =
-          " -not -path '*/" + bowerrc.toString().replace(/\/$/, '') + "/*'"
+        more_patterns = (
+          " -not -path '*/" +
+          bowerrc.toString().replace(/\/$/, '') +
+          "/*'"
+        ).split(' ')
       } else {
-        more_patterns =
-          '| findstr /i /v \\' + bowerrc.toString().replace(/\/$/, '') + '\\'
+        more_patterns = (
+          '| findstr /i /v \\' +
+          bowerrc.toString().replace(/\/$/, '') +
+          '\\'
+        ).split(' ')
       }
     }
   }
@@ -474,15 +482,26 @@
   } else if ((args.options.disable || '').split(',').indexOf('search') === -1) {
     console.log('==> Scanning for reports')
     var _files
+    var _findArgs
     if (!isWindows) {
-      _files = execSync('find ' + root + ' ' + patterns + more_patterns)
+      // @TODO support for a root directory
+      // It's not straightforward due to the nature of the find command
+      _findArgs = [root].concat(patterns)
+      if (more_patterns) {
+        _findArgs.concat(more_patterns)
+      }
+      _files = execFileSync('find', _findArgs)
         .toString()
         .trim()
         .split('\n')
     } else {
       // @TODO support for a root directory
       // It's not straightforward due to the nature of the dir command
-      _files = execSync('dir ' + patterns + more_patterns)
+      _findArgs = [root].concat(winPatterns)
+      if (more_patterns) {
+        _findArgs.concat(more_patterns)
+      }
+      _files = execSync('dir ' + winPatterns.join(' ') + more_patterns)
         .toString()
         .trim()
         .split('\r\n')
```
