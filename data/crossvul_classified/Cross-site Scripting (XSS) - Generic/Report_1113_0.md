# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1113_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1113_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 58-98 of the vulnerable file.

    opts._visited = []
  }
  if (!opts._refs) {
    opts.references = []
    opts._refs = new Ref(opts.references)
  }

  if (util.isNull(source)) {
    out += 'null'
  } else if (util.isArray(source)) {
    tmp = source.map(function (item) {
      return serialize(item, opts)
    })
    out += '[' + tmp.join(', ') + ']'
  } else if (util.isFunction(source)) {
    tmp = source.toString()
    // append function to es6 function within obj
    out += !/^\s*(function|\([^)]*\)\s*=>)/m.test(tmp) ? 'function ' + tmp : tmp
  } else if (util.isObject(source)) {
    if (util.isRegExp(source)) {
      out += source.toString()
    } else if (util.isDate(source)) {
      out += 'new Date("' + source.toJSON() + '")'
    } else if (util.isError(source)) {
      out += 'new Error(' + (source.message ? '"' + source.message + '"' : '') + ')'
    } else if (util.isBuffer(source)) {
      // check for buffer first otherwise tests fail on node@4.4
      // looks like buffers are accidentially detected as typed arrays
      out += "Buffer.from('" + source.toString('base64') + "', 'base64')"
    } else if ((type = util.isTypedArray(source))) {
      tmp = []
      for (i = 0; i < source.length; i++) {
        tmp.push(source[i])
      }
      out += 'new ' + type + '(' +
        '[' + tmp.join(', ') + ']' +
        ')'
    } else {
      tmp = []
      // copy properties if not circular
      if (!~opts._visited.indexOf(source)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
     out += !/^\s*(function|\([^)]*\)\s*=>)/m.test(tmp) ? 'function ' + tmp : tmp
   } else if (util.isObject(source)) {
     if (util.isRegExp(source)) {
-      out += source.toString()
+      out += 'new RegExp("' + source.source + '", "' + source.flags + '")'
     } else if (util.isDate(source)) {
       out += 'new Date("' + source.toJSON() + '")'
     } else if (util.isError(source)) {
```
