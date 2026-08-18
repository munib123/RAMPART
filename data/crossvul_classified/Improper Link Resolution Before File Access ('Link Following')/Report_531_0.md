# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 531_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `531_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 234-277 of the vulnerable file.

  } else {
    var global = this._global
    var extended = this._extended

    // extendedHeader only applies to one entry, so once we start
    // an entry, it's over.
    this._extended = null
  }
  entry = new EntryType(header, extended, global)
  entry.meta = meta

  // only proxy data events of normal files.
  if (!meta) {
    entry.on("data", function (c) {
      me.emit("data", c)
    })
  }

  if (onend) entry.on("end", onend)

  if (entry.type === "File" && this._hardLinks[entry.path]) {
    ev = "ignoredEntry"
  }

  this._entry = entry

  if (entry.type === "Link") {
    this._hardLinks[entry.path] = entry
  }

  var me = this

  entry.on("pause", function () {
    me.pause()
  })

  entry.on("resume", function () {
    me.resume()
  })

  if (this.listeners("*").length) {
    this.emit("*", ev, entry)
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,10 +251,6 @@
 
   if (onend) entry.on("end", onend)
 
-  if (entry.type === "File" && this._hardLinks[entry.path]) {
-    ev = "ignoredEntry"
-  }
-
   this._entry = entry
 
   if (entry.type === "Link") {
```
