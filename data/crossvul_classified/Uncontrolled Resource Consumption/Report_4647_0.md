# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4647_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4647_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 63-103 of the vulnerable file.

    .split(/\./).map(function (part) {
      return part.replace(/\1/g, '\\.')
      .replace(/\2LITERAL\\1LITERAL\2/g, '\u0001')
    })
}

function decode (str) {
  var out = {}
  var p = out
  var section = null
  //          section     |key      = value
  var re = /^\[([^\]]*)\]$|^([^=]+)(=(.*))?$/i
  var lines = str.split(/[\r\n]+/g)

  lines.forEach(function (line, _, __) {
    if (!line || line.match(/^\s*[;#]/)) return
    var match = line.match(re)
    if (!match) return
    if (match[1] !== undefined) {
      section = unsafe(match[1])
      p = out[section] = out[section] || {}
      return
    }
    var key = unsafe(match[2])
    var value = match[3] ? unsafe(match[4]) : true
    switch (value) {
      case 'true':
      case 'false':
      case 'null': value = JSON.parse(value)
    }

    // Convert keys with '[]' suffix to an array
    if (key.length > 2 && key.slice(-2) === '[]') {
      key = key.substring(0, key.length - 2)
      if (!p[key]) {
        p[key] = []
      } else if (!Array.isArray(p[key])) {
        p[key] = [p[key]]
      }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,12 @@
     if (!match) return
     if (match[1] !== undefined) {
       section = unsafe(match[1])
+      if (section === '__proto__') {
+        // not allowed
+        // keep parsing the section, but don't attach it.
+        p = {}
+        return
+      }
       p = out[section] = out[section] || {}
       return
     }
@@ -94,6 +100,7 @@
     // Convert keys with '[]' suffix to an array
     if (key.length > 2 && key.slice(-2) === '[]') {
       key = key.substring(0, key.length - 2)
+      if (key === '__proto__') return
       if (!p[key]) {
         p[key] = []
       } else if (!Array.isArray(p[key])) {
@@ -125,6 +132,7 @@
     var l = parts.pop()
     var nl = l.replace(/\\\./g, '.')
     parts.forEach(function (part, _, __) {
+      if (part === '__proto__') return
       if (!p[part] || typeof p[part] !== 'object') p[part] = {}
       p = p[part]
     })
```
