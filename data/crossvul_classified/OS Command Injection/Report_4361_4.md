# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4361_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 23-63 of the vulnerable file.

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
      let urlSanitized = '';
      const s = util.sanitizeShellString(url);
      for (let i = 0; i <= 2000; i++) {
        if (!(s[i] === undefined ||
          s[i] === ' ' ||
          s[i] === '{' ||
          s[i] === '}')) {
          const sl = s[i].toLowerCase();
          if (sl && sl[0] && !sl[1]) {
            urlSanitized = urlSanitized + sl[0];
          }
        }
      }
      let result = {
        url: urlSanitized,
        ok: false,
        status: 404,
        ms: -1
      };
      try {
        if (urlSanitized && !util.isPrototypePolluted()) {
          let t = Date.now();
          if (_linux || _freebsd || _openbsd || _netbsd || _darwin || _sunos) {
            let args = ' -I --connect-timeout 5 -m 5 ' + urlSanitized + ' 2>/dev/null | head -n 1 | cut -d " " -f2';
            let cmd = 'curl';
            exec(cmd + args, function (error, stdout) {
              let statusCode = parseInt(stdout.toString());
              result.status = statusCode || 404;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,7 @@
           s[i] === ' ' ||
           s[i] === '{' ||
           s[i] === '}')) {
+          s[i].__proto__.toLowerCase = util.stringToLower;
           const sl = s[i].toLowerCase();
           if (sl && sl[0] && !sl[1]) {
             urlSanitized = urlSanitized + sl[0];
```
