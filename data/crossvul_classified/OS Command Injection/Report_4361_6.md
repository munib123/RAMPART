# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4361_6
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 81-121 of the vulnerable file.

  }
  return result;
}

// --------------------------
// PS - services
// pass a comma separated string with services to check (mysql, apache, postgresql, ...)
// this function gives an array back, if the services are running.

function services(srv, callback) {

  // fallback - if only callback is given
  if (util.isFunction(srv) && !callback) {
    callback = srv;
    srv = '';
  }

  return new Promise((resolve) => {
    process.nextTick(() => {
      if (srv) {
        let srvString = util.sanitizeShellString(srv);
        srvString = srvString.trim().toLowerCase().replace(/, /g, '|').replace(/,+/g, '|');
        if (srvString === '') {
          srvString = '*';
        }
        if (util.isPrototypePolluted() && srvString !== '*') {
          srvString = '------';
        }
        let srvs = srvString.split('|');
        let result = [];
        let dataSrv = [];
        let allSrv = [];

        if (_linux || _freebsd || _openbsd || _netbsd || _darwin) {
          if ((_linux || _freebsd || _openbsd || _netbsd) && srvString === '*') {
            srvString = '';
            let tmpsrv = execSync('service --status-all 2> /dev/null').toString().split('\n');
            for (const s of tmpsrv) {
              const parts = s.split(']');
              if (parts.length === 2) {
                srvString += (srvString !== '' ? '|' : '') + parts[1].trim();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,7 +98,18 @@
   return new Promise((resolve) => {
     process.nextTick(() => {
       if (srv) {
-        let srvString = util.sanitizeShellString(srv);
+        let srvString = '';
+        srvString.__proto__.toLowerCase = util.stringToLower;
+        srvString.__proto__.replace = util.stringReplace;
+        srvString.__proto__.trim = util.stringTrim;
+
+        const s = util.sanitizeShellString(srv);
+        for (let i = 0; i <= 2000; i++) {
+          if (!(s[i] === undefined)) {
+            srvString = srvString + s[i];
+          }
+        }
+
         srvString = srvString.trim().toLowerCase().replace(/, /g, '|').replace(/,+/g, '|');
         if (srvString === '') {
           srvString = '*';
```
