# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 1945_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1945_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 92-132 of the vulnerable file.

exports.dockerInfo = dockerInfo;

function dockerContainers(all, callback) {

  function inContainers(containers, id) {
    let filtered = containers.filter(obj => {
      /**
       * @namespace
       * @property {string}  Id
       */
      return (obj.Id && (obj.Id === id));
    });
    return (filtered.length > 0);
  }

  // fallback - if only callback is given
  if (util.isFunction(all) && !callback) {
    callback = all;
    all = false;
  }

  all = all || false;
  let result = [];
  return new Promise((resolve) => {
    process.nextTick(() => {
      if (!_docker_socket) {
        _docker_socket = new DockerSocket();
      }
      const workload = [];

      _docker_socket.listContainers(all, data => {
        let docker_containers = {};
        try {
          docker_containers = data;
          if (docker_containers && Object.prototype.toString.call(docker_containers) === '[object Array]' && docker_containers.length > 0) {
            // GC in _docker_container_stats
            for (let key in _docker_container_stats) {
              if ({}.hasOwnProperty.call(_docker_container_stats, key)) {
                if (!inContainers(docker_containers, key)) { delete _docker_container_stats[key]; }
              }
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,6 +109,9 @@
     callback = all;
     all = false;
   }
+  if (typeof all !== 'boolean' && all !== undefined) {
+    all = false;
+  }
 
   all = all || false;
   let result = [];
@@ -185,16 +188,20 @@
 // container inspect (for one container)
 
 function dockerContainerInspect(containerID, payload) {
-  containerID = containerID || '';
-  return new Promise((resolve) => {
-    process.nextTick(() => {
-      if (containerID) {
+  return new Promise((resolve) => {
+    process.nextTick(() => {
+      containerID = containerID || '';
+      if (typeof containerID !== 'string') {
+        resolve();
+      }
+      const containerIdSanitized = (util.isPrototypePolluted() ? '' : util.sanitizeShellString(containerID, true)).trim();
+      if (containerIdSanitized) {
 
         if (!_docker_socket) {
           _docker_socket = new DockerSocket();
         }
 
-        _docker_socket.getInspect(containerID.trim(), data => {
+        _docker_socket.getInspect(containerIdSanitized.trim(), data => {
           try {
             resolve({
               id: payload.Id,
@@ -325,18 +332,38 @@
 function dockerContainerStats(containerIDs, callback) {
 
   let containerArray = [];
-  // fallback - if only callback is given
-  if (util.isFunction(containerIDs) && !callback) {
-    callback = containerIDs;
-    containerArray = ['*'];
-  } else {
-    containerIDs = containerIDs || '*';
-    containerIDs = containerIDs.trim().toLowerCase().replace(/,+/g, '|');
-    containerArray = containerIDs.split('|');
-  }
-
-  return new Promise((resolve) => {
-    process.nextTick(() => {
+  return new Promise((resolve) => {
+    process.nextTick(() => {
+
+      // fallback - if only callback is given
+      if (util.isFunction(containerIDs) && !callback) {
+        callback = containerIDs;
+        containerArray = ['*'];
+      } else {
+        containerIDs = containerIDs || '*';
+        if (typeof containerIDs !== 'string') {
+          if (callback) { callback([]); }
+          return resolve([]);
+        }
+        let containerIDsSanitized = '';
+        containerIDsSanitized.__proto__.toLowerCase = util.stringToLower;
+        containerIDsSanitized.__proto__.replace = util.stringReplace;
+        containerIDsSanitized.__proto__.trim = util.stringTrim;
+
+        const s = (util.isPrototypePolluted() ? '' : util.sanitizeShellString(containerIDs, true)).trim();
+        for (let i = 0; i <= 2000; i++) {
+          if (!(s[i] === undefined)) {
+            s[i].__proto__.toLowerCase = util.stringToLower;
+            const sl = s[i].toLowerCase();
+            if (sl && sl[0] && !sl[1]) {
+              containerIDsSanitized = containerIDsSanitized + sl[0];
+            }
+          }
+        }
+
+        containerIDsSanitized = containerIDsSanitized.trim().toLowerCase().replace(/,+/g, '|');
+        containerArray = containerIDs.split('|');
+      }
 
       const result = [];
 
@@ -444,17 +471,22 @@
 // container processes (for one container)
 
 function dockerContainerProcesses(containerID, callback) {
-  containerID = containerID || '';
   let result = [];
   return new Promise((resolve) => {
     process.nextTick(() => {
-      if (containerID) {
+      containerID = containerID || '';
+      if (typeof containerID !== 'string') {
+        resolve(result);
+      }
+      const containerIdSanitized = (util.isPrototypePolluted() ? '' : util.sanitizeShellString(containerID, true)).trim();
+
+      if (containerIdSanitized) {
 
         if (!_docker_socket) {
           _docker_socket = new DockerSocket();
         }
 
-        _docker_socket.getProcesses(containerID, data => {
+        _docker_socket.getProcesses(containerIdSanitized, data => {
           /**
            * @namespace
            * @property {Array}  Titles
```
