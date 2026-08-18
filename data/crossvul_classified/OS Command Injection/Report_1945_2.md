# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 1945_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1945_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 956-1004 of the vulnerable file.

    _network[iface].tx_sec = result.tx_sec;
    _network[iface].ms = Date.now();
    _network[iface].last_ms = result.ms;
    _network[iface].operstate = operstate;
  } else {
    if (!_network[iface]) { _network[iface] = {}; }
    _network[iface].rx_bytes = rx_bytes;
    _network[iface].tx_bytes = tx_bytes;
    _network[iface].rx_sec = null;
    _network[iface].tx_sec = null;
    _network[iface].ms = Date.now();
    _network[iface].last_ms = 0;
    _network[iface].operstate = operstate;
  }
  return result;
}

function networkStats(ifaces, callback) {

  let ifacesArray = [];
  // fallback - if only callback is given
  if (util.isFunction(ifaces) && !callback) {
    callback = ifaces;
    ifacesArray = [getDefaultNetworkInterface()];
  } else {
    ifaces = ifaces || getDefaultNetworkInterface();
    ifaces = ifaces.trim().toLowerCase().replace(/,+/g, '|');
    ifacesArray = ifaces.split('|');
  }

  return new Promise((resolve) => {
    process.nextTick(() => {

      const result = [];

      const workload = [];
      if (ifacesArray.length && ifacesArray[0].trim() === '*') {
        ifacesArray = [];
        networkInterfaces(false).then(allIFaces => {
          for (let iface of allIFaces) {
            ifacesArray.push(iface.iface);
          }
          networkStats(ifacesArray.join(',')).then(result => {
            if (callback) { callback(result); }
            resolve(result);
          });
        });
      } else {
        for (let iface of ifacesArray) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -973,18 +973,28 @@
 function networkStats(ifaces, callback) {
 
   let ifacesArray = [];
-  // fallback - if only callback is given
-  if (util.isFunction(ifaces) && !callback) {
-    callback = ifaces;
-    ifacesArray = [getDefaultNetworkInterface()];
-  } else {
-    ifaces = ifaces || getDefaultNetworkInterface();
-    ifaces = ifaces.trim().toLowerCase().replace(/,+/g, '|');
-    ifacesArray = ifaces.split('|');
-  }
 
   return new Promise((resolve) => {
     process.nextTick(() => {
+
+      // fallback - if only callback is given
+      if (util.isFunction(ifaces) && !callback) {
+        callback = ifaces;
+        ifacesArray = [getDefaultNetworkInterface()];
+      } else {
+        if (typeof ifaces !== 'string' && ifaces !== undefined) {
+          if (callback) { callback([]); }
+          return resolve([]);
+        }
+        ifaces = ifaces || getDefaultNetworkInterface();
+
+        ifaces.__proto__.toLowerCase = util.stringToLower;
+        ifaces.__proto__.replace = util.stringReplace;
+        ifaces.__proto__.trim = util.stringTrim;
+
+        ifaces = ifaces.trim().toLowerCase().replace(/,+/g, '|');
+        ifacesArray = ifaces.split('|');
+      }
 
       const result = [];
 
```
