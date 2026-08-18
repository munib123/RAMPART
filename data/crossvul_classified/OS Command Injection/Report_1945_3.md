# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 1945_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1945_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 82-122 of the vulnerable file.

    result = parts[4] + '-' + ('0' + ('JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC'.indexOf(parts[1].toUpperCase()) / 3 + 1)).slice(-2) + '-' + ('0' + parts[2]).slice(-2) + ' ' + parts[3];
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
      if (typeof srv !== "string") {
        if (callback) { callback([]); }
        return resolve([]);
      }

      if (srv) {
        let srvString = '';
        srvString.__proto__.toLowerCase = util.stringToLower;
        srvString.__proto__.replace = util.stringReplace;
        srvString.__proto__.trim = util.stringTrim;

        const s = util.sanitizeShellString(srv);
        for (let i = 0; i <= 2000; i++) {
          if (!(s[i] === undefined)) {
            srvString = srvString + s[i];
          }
        }

        srvString = srvString.trim().toLowerCase().replace(/, /g, '|').replace(/,+/g, '|');
        if (srvString === '') {
          srvString = '*';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
 
   return new Promise((resolve) => {
     process.nextTick(() => {
-      if (typeof srv !== "string") {
+      if (typeof srv !== 'string') {
         if (callback) { callback([]); }
         return resolve([]);
       }
@@ -892,6 +892,13 @@
   return new Promise((resolve) => {
     process.nextTick(() => {
 
+      proc = proc || '';
+
+      if (typeof proc !== 'string') {
+        if (callback) { callback([]); }
+        return resolve([]);
+      }
+
       let processesString = '';
       processesString.__proto__.toLowerCase = util.stringToLower;
       processesString.__proto__.replace = util.stringReplace;
```
