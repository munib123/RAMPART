# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4622_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4622_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

function reducer(result, arg)
{
  arg = arg.split('=')

  // Get key node
  const keypath = arg.shift().split('.')

  let key = keypath.shift()
  let node = result

  while(keypath.length)
  {
    node[key] = node[key] || {}
    node = node[key]

    key = keypath.shift()
  }

  // Get value
  let val = true
  if(arg.length)
  {
    val = arg.join('=').split(',')
    if(val.length === 1) val = val[0]
  }

  // Store value
  node[key] = val

  return result
}


/**
 * This function takes the `cmdline` from `/proc/cmdline` **showed below in
 * the example** and splits it into key/value pairs
 * @access private
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,17 +4,6 @@
 
   // Get key node
   const keypath = arg.shift().split('.')
-
-  let key = keypath.shift()
-  let node = result
-
-  while(keypath.length)
-  {
-    node[key] = node[key] || {}
-    node = node[key]
-
-    key = keypath.shift()
-  }
 
   // Get value
   let val = true
@@ -24,8 +13,29 @@
     if(val.length === 1) val = val[0]
   }
 
+  let key = keypath.shift()
+
+  if(!keypath.length) return {...result, [key]: val}
+
+  if(!result.hasOwnProperty(key)) result = {...result, [key]: {}}
+
+  let newKey
+  let newNode
+  let node = result
+
+  while(true)
+  {
+    newKey = keypath.shift()
+    newNode = node[key]
+
+    if(!keypath.length) break
+
+    node = node[key] = {...newNode, [newKey]: newNode[newKey] || {}}
+    key = newKey
+  }
+
   // Store value
-  node[key] = val
+  node[key] = {...newNode, [newKey]: val}
 
   return result
 }
```
