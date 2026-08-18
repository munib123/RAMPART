# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4205_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4205_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

const core = require('@actions/core');
const { exec } = require('child_process');

function main() {
  try {
    let tag = process.env.GITHUB_REF;
    if (core.getInput('tag')) {
      tag = `refs/tags/${core.getInput('tag')}`;
    }

    exec(`git for-each-ref --format='%(contents)' ${tag}`, (err, stdout) => {
      if (err) {
        core.setFailed(err);
      } else {
        core.setOutput('git-tag-annotation', stdout);
      }
    });
  } catch (error) {
    core.setFailed(error.message);
  }
}

module.exports = main;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,10 @@
 const core = require('@actions/core');
 const { exec } = require('child_process');
+
+// Based on https://stackoverflow.com/a/22827128
+function escapeShellArg(arg) {
+  return arg.replace(/'/g, `'\\''`);
+}
 
 function main() {
   try {
@@ -8,13 +13,16 @@
       tag = `refs/tags/${core.getInput('tag')}`;
     }
 
-    exec(`git for-each-ref --format='%(contents)' ${tag}`, (err, stdout) => {
-      if (err) {
-        core.setFailed(err);
-      } else {
-        core.setOutput('git-tag-annotation', stdout);
-      }
-    });
+    exec(
+      `git for-each-ref --format='%(contents)' '${escapeShellArg(tag)}'`,
+      (err, stdout) => {
+        if (err) {
+          core.setFailed(err);
+        } else {
+          core.setOutput('git-tag-annotation', stdout);
+        }
+      },
+    );
   } catch (error) {
     core.setFailed(error.message);
   }
```
