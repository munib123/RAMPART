# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 4512_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4512_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

var contra = require('contra'),
    path = require('path'),
    fUtils = require('./files'),
    cp = require('child_process');

var gitApp = 'git', gitExtra = { env: process.env };


var escapeQuotes = function (str) {
  if (typeof str === 'string') {
    return str.replace(/(["$`\\])/g, '\\$1');
  } else {
    return str;
  }
};

module.exports.isRepositoryClean = function (callback) {
  cp.exec(gitApp + ' ' + [ 'ls-files', '-m' ].join(' '), gitExtra, function (er, stdout, stderr) {
    // makeCommit parly inspired and taken from NPM version module
    var lines = stdout.trim().split('\n').filter(function (line) {
      var file = path.basename(line.replace(/.{1,2}\s+/, ''));
      return line.trim() && !line.match(/^\?\? /) && !fUtils.isPackageFile(line);
    }).map(function (line) {
      return line.trim()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,62 +1,71 @@
-var contra = require('contra'),
-    path = require('path'),
-    fUtils = require('./files'),
-    cp = require('child_process');
+var contra = require("contra"),
+  path = require("path"),
+  fUtils = require("./files"),
+  cp = require("child_process");
 
-var gitApp = 'git', gitExtra = { env: process.env };
-
+var gitApp = "git",
+  gitExtra = { env: process.env };
 
 var escapeQuotes = function (str) {
-  if (typeof str === 'string') {
-    return str.replace(/(["$`\\])/g, '\\$1');
+  if (typeof str === "string") {
+    return '"' + str.replace(/(["'$`\\])/g, "\\$1") + '"';
   } else {
     return str;
   }
 };
 
 module.exports.isRepositoryClean = function (callback) {
-  cp.exec(gitApp + ' ' + [ 'ls-files', '-m' ].join(' '), gitExtra, function (er, stdout, stderr) {
+  cp.exec(gitApp + " " + ["ls-files", "-m"].join(" "), gitExtra, function (
+    er,
+    stdout,
+    stderr
+  ) {
     // makeCommit parly inspired and taken from NPM version module
-    var lines = stdout.trim().split('\n').filter(function (line) {
-      var file = path.basename(line.replace(/.{1,2}\s+/, ''));
-      return line.trim() && !line.match(/^\?\? /) && !fUtils.isPackageFile(line);
-    }).map(function (line) {
-      return line.trim()
-    });
+    var lines = stdout
+      .trim()
+      .split("\n")
+      .filter(function (line) {
+        var file = path.basename(line.replace(/.{1,2}\s+/, ""));
+        return (
+          line.trim() && !line.match(/^\?\? /) && !fUtils.isPackageFile(line)
+        );
+      })
+      .map(function (line) {
+        return line.trim();
+      });
 
     if (lines.length) {
-      return callback(new Error('Git working directory not clean.\n'+lines.join('\n')));
+      return callback(
+        new Error("Git working directory not clean.\n" + lines.join("\n"))
+      );
     }
     return callback();
   });
 };
 
 module.exports.checkout = function (callback) {
-  cp.exec(gitApp + ' checkout -- .', gitExtra, callback);
+  cp.exec(gitApp + " checkout -- .", gitExtra, callback);
 };
 
 module.exports.commit = function (files, message, newVer, tagName, callback) {
-  message = message.replace('%s', newVer).replace('"', '').replace("'", '');
-  files = files.map(function (file) {
-    return '"' + escapeQuotes(file) + '"';
-  }).join(' ');
+  message = escapeQuotes(message.replace("%s", newVer));
+  files = files.map(escapeQuotes).join(" ");
   var functionSeries = [
     function (done) {
-      cp.exec(gitApp + ' add ' + files, gitExtra, done);
+      cp.exec(gitApp + " add " + files, gitExtra, done);
     },
 
     function (done) {
-      cp.exec([gitApp, 'commit', '-m', '"' + message + '"'].join(' '), gitExtra, done);
+      cp.exec([gitApp, "commit", "-m", message].join(" "), gitExtra, done);
     },
 
     function (done) {
       cp.exec(
-        [
-          gitApp, 'tag', '-a', tagName, '-m', '"' + message + '"'
-        ].join(' '),
-        gitExtra, done
+        [gitApp, "tag", "-a", tagName, "-m", message].join(" "),
+        gitExtra,
+        done
       );
-    }
+    },
   ];
   contra.series(functionSeries, callback);
 };
```
