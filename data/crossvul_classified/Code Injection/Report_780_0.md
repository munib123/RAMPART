# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 780_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `780_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 28-68 of the vulnerable file.

  }
  return key
}

function isIndex (k) {
  return /^\d+$/.test(k)
}

function isObject (val) {
  return Object.prototype.toString.call(val) === '[object Object]'
}

function isArrayOrObject (val) {
  return Object(val) === val
}

function isEmptyObject (val) {
  return Object.keys(val).length === 0
}

function parsePath (path, sep) {
  if (path.indexOf('[') >= 0) {
    path = path.replace(/\[/g, '.').replace(/]/g, '')
  }
  return path.split(sep)
}

var hasOwnProperty = Object.prototype.hasOwnProperty

function DotObject (separator, override, useArray, useBrackets) {
  if (!(this instanceof DotObject)) {
    return new DotObject(separator, override, useArray, useBrackets)
  }

  if (typeof override === 'undefined') override = false
  if (typeof useArray === 'undefined') useArray = true
  if (typeof useBrackets === 'undefined') useBrackets = true
  this.separator = separator || '.'
  this.override = override
  this.useArray = useArray
  this.useBrackets = useBrackets
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,11 +45,22 @@
   return Object.keys(val).length === 0
 }
 
+const blacklist = ['__proto__', 'prototype', 'constructor']
+
 function parsePath (path, sep) {
   if (path.indexOf('[') >= 0) {
     path = path.replace(/\[/g, '.').replace(/]/g, '')
   }
-  return path.split(sep)
+
+  const parts = path.split(sep)
+
+  const check = parts.filter(part => blacklist.indexOf(part) === -1)
+
+  if (check.length !== parts.length) {
+    throw Error('Refusing to update blacklisted property ' + path)
+  }
+
+  return parts
 }
 
 var hasOwnProperty = Object.prototype.hasOwnProperty
@@ -83,8 +94,7 @@
   var k = a.shift()
 
   if (a.length > 0) {
-    obj[k] = obj[k] ||
-      (this.useArray && isIndex(a[0]) ? [] : {})
+    obj[k] = obj[k] || (this.useArray && isIndex(a[0]) ? [] : {})
 
     if (!isArrayOrObject(obj[k])) {
       if (this.override) {
@@ -102,8 +112,7 @@
 
     this._fill(a, obj[k], v, mod)
   } else {
-    if (!this.override &&
-      isArrayOrObject(obj[k]) && !isEmptyObject(obj[k])) {
+    if (!this.override && isArrayOrObject(obj[k]) && !isEmptyObject(obj[k])) {
       if (!(isArrayOrObject(v) && isEmptyObject(v))) {
         throw new Error("Trying to redefine non-empty obj['" + k + "']")
       }
@@ -195,7 +204,7 @@
   for (i = 0; i < keys.length; i++) {
     key = parseKey(keys[i], obj)
     if (obj && typeof obj === 'object' && key in obj) {
-      if (i === (keys.length - 1)) {
+      if (i === keys.length - 1) {
         if (remove) {
           val = obj[key]
           if (reindexArray && Array.isArray(obj)) {
@@ -221,7 +230,9 @@
     }
   }
   if (remove && Array.isArray(obj)) {
-    obj = obj.filter(function (n) { return n !== undefined })
+    obj = obj.filter(function (n) {
+      return n !== undefined
+    })
   }
   return obj
 }
@@ -279,7 +290,9 @@
       keys = this.cleanup[i].split('.')
       root = keys.splice(0, -1).join('.')
       ret = root ? this.pick(root, obj) : obj
-      ret = ret[keys[0]].filter(function (v) { return v !== undefined })
+      ret = ret[keys[0]].filter(function (v) {
+        return v !== undefined
+      })
       this.set(this.cleanup[i], ret, obj)
     }
     this.cleanup = []
@@ -336,13 +349,21 @@
  * @param {Function|Array} mods
  * @param {Boolean} merge
  */
-DotObject.prototype.transfer = function (source, target, obj1, obj2, mods, merge) {
+DotObject.prototype.transfer = function (
+  source,
+  target,
+  obj1,
+  obj2,
+  mods,
+  merge
+) {
   if (typeof mods === 'function' || Array.isArray(mods)) {
-    this.set(target,
-      _process(
-        this.pick(source, obj1, true),
-        mods
-      ), obj2, merge)
+    this.set(
+      target,
+      _process(this.pick(source, obj1, true), mods),
+      obj2,
+      merge
+    )
   } else {
     merge = mods
     this.set(target, this.pick(source, obj1, true), obj2, merge)
@@ -367,16 +388,16 @@
  */
 DotObject.prototype.copy = function (source, target, obj1, obj2, mods, merge) {
   if (typeof mods === 'function' || Array.isArray(mods)) {
-    this.set(target,
+    this.set(
+      target,
       _process(
         // clone what is picked
-        JSON.parse(
-          JSON.stringify(
-            this.pick(source, obj1, false)
-          )
-        ),
+        JSON.parse(JSON.stringify(this.pick(source, obj1, false))),
         mods
-      ), obj2, merge)
+      ),
+      obj2,
+      merge
+    )
   } else {
     merge = mods
     this.set(target, this.pick(source, obj1, false), obj2, merge)
@@ -408,7 +429,7 @@
 
   for (i = 0; i < keys.length; i++) {
     key = keys[i]
-    if (i === (keys.length - 1)) {
+    if (i === keys.length - 1) {
       if (merge && isObject(val) && isObject(obj[key])) {
         for (k in val) {
           if (hasOwnProperty.call(val, k)) {
@@ -447,14 +468,14 @@
  *
  *   var obj = {
  *     "id": 1,
-  *    "some": {
-  *      "thing": "else"
-  *    }
+ *    "some": {
+ *      "thing": "else"
+ *    }
  *   }
  *
  *   var transform = {
  *     "id": "nr",
-  *    "some.thing": "name"
+ *    "some.thing": "name"
  *   }
  *
  *   var tgt = dot.transform(transform, obj)
@@ -466,9 +487,11 @@
 DotObject.prototype.transform = function (recipe, obj, tgt) {
   obj = obj || {}
   tgt = tgt || {}
-  Object.keys(recipe).forEach(function (key) {
-    this.set(recipe[key], this.pick(key, obj), tgt)
-  }.bind(this))
+  Object.keys(recipe).forEach(
+    function (key) {
+      this.set(recipe[key], this.pick(key, obj), tgt)
+    }.bind(this)
+  )
   return tgt
 }
 
@@ -494,31 +517,33 @@
   path = path || []
   var isArray = Array.isArray(obj)
 
-  Object.keys(obj).forEach(function (key) {
-    var index = isArray && this.useBrackets ? '[' + key + ']' : key
-    if (
-      (
+  Object.keys(obj).forEach(
+    function (key) {
+      var index = isArray && this.useBrackets ? '[' + key + ']' : key
+      if (
         isArrayOrObject(obj[key]) &&
-        (
-          (isObject(obj[key]) && !isEmptyObject(obj[key])) ||
-          (Array.isArray(obj[key]) && (!this.keepArray && (obj[key].length !== 0)))
-        )
-      )
-    ) {
-      if (isArray && this.useBrackets) {
-        var previousKey = path[path.length - 1] || ''
-        return this.dot(obj[key], tgt, path.slice(0, -1).concat(previousKey + index))
+        ((isObject(obj[key]) && !isEmptyObject(obj[key])) ||
+          (Array.isArray(obj[key]) && !this.keepArray && obj[key].length !== 0))
+      ) {
+        if (isArray && this.useBrackets) {
+          var previousKey = path[path.length - 1] || ''
+          return this.dot(
+            obj[key],
+            tgt,
+            path.slice(0, -1).concat(previousKey + index)
+          )
+        } else {
+          return this.dot(obj[key], tgt, path.concat(index))
+        }
       } else {
-        return this.dot(obj[key], tgt, path.concat(index))
-      }
-    } else {
-      if (isArray && this.useBrackets) {
-        tgt[path.join(this.separator).concat('[' + key + ']')] = obj[key]
-      } else {
-        tgt[path.concat(index).join(this.separator)] = obj[key]
-      }
-    }
-  }.bind(this))
+        if (isArray && this.useBrackets) {
+          tgt[path.join(this.separator).concat('[' + key + ']')] = obj[key]
+        } else {
+          tgt[path.concat(index).join(this.separator)] = obj[key]
+        }
+      }
+    }.bind(this)
+  )
   return tgt
 }
 
@@ -532,9 +557,8 @@
 DotObject.set = wrap('set')
 DotObject.delete = wrap('delete')
 DotObject.del = DotObject.remove = wrap('remove')
-DotObject.dot = wrap('dot')
-
-;['override', 'overwrite'].forEach(function (prop) {
+DotObject.dot = wrap('dot');
+['override', 'overwrite'].forEach(function (prop) {
   Object.defineProperty(DotObject, prop, {
     get: function () {
       return dotDefault.override
@@ -543,9 +567,8 @@
       dotDefault.override = !!val
     }
   })
-})
-
-;['useArray', 'keepArray', 'useBrackets'].forEach(function (prop) {
+});
+['useArray', 'keepArray', 'useBrackets'].forEach(function (prop) {
   Object.defineProperty(DotObject, prop, {
     get: function () {
       return dotDefault[prop]
```
