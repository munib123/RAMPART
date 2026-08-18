# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 4635_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4635_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 17-57 of the vulnerable file.

const util = require('./util');

let _platform = process.platform;

const _linux = (_platform === 'linux');
const _darwin = (_platform === 'darwin');
const _windows = (_platform === 'win32');
const _freebsd = (_platform === 'freebsd');
const _openbsd = (_platform === 'openbsd');
const _netbsd = (_platform === 'netbsd');
const _sunos = (_platform === 'sunos');

// --------------------------
// check if external site is available

function inetChecksite(url, callback) {

  return new Promise((resolve) => {
    process.nextTick(() => {

      const urlSanitized = util.sanitizeShellString(url).toLowerCase();
      let result = {
        url: urlSanitized,
        ok: false,
        status: 404,
        ms: -1
      };
      if (urlSanitized) {
        let t = Date.now();
        if (_linux || _freebsd || _openbsd || _netbsd || _darwin || _sunos) {
          let args = ' -I --connect-timeout 5 -m 5 ' + urlSanitized + ' 2>/dev/null | head -n 1 | cut -d " " -f2';
          let cmd = 'curl';
          exec(cmd + args, function (error, stdout) {
            let statusCode = parseInt(stdout.toString());
            result.status = statusCode || 404;
            result.ok = !error && (statusCode === 200 || statusCode === 301 || statusCode === 302 || statusCode === 304);
            result.ms = (result.ok ? Date.now() - t : -1);
            if (callback) { callback(result); }
            resolve(result);
          });
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,13 @@
   return new Promise((resolve) => {
     process.nextTick(() => {
 
-      const urlSanitized = util.sanitizeShellString(url).toLowerCase();
+      let urlSanitized = util.sanitizeShellString(url).toLowerCase();
+      urlSanitized = urlSanitized.replace(/ /g, '');
+      urlSanitized = urlSanitized.replace(/\$/g, '');
+      urlSanitized = urlSanitized.replace(/\(/g, '');
+      urlSanitized = urlSanitized.replace(/\)/g, '');
+      urlSanitized = urlSanitized.replace(/{/g, '');
+      urlSanitized = urlSanitized.replace(/}/g, '');
       let result = {
         url: urlSanitized,
         ok: false,
```
