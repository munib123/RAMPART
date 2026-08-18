# CrossVul Fix Pair: Modification of Assumed-Immutable Data (MAID) in javascript
**Pair ID:** 4192_0
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-471
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4192_0`)

## Vulnerability Information & PoC

## Description
Modification of Assumed-Immutable Data (MAID) - This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is.

## Vulnerable Code
```javascript
Lines 95-135 of the vulnerable file.

    }

    function getShallowProperty(obj, prop) {
      if (hasShallowProperty(obj, prop)) {
        return obj[prop];
      }
    }

    function set(obj, path, value, doNotReplace){
      if (typeof path === 'number') {
        path = [path];
      }
      if (!path || path.length === 0) {
        return obj;
      }
      if (typeof path === 'string') {
        return set(obj, path.split('.').map(getKey), value, doNotReplace);
      }
      var currentPath = path[0];
      var currentValue = getShallowProperty(obj, currentPath);
      if (path.length === 1) {
        if (currentValue === void 0 || !doNotReplace) {
          obj[currentPath] = value;
        }
        return currentValue;
      }

      if (currentValue === void 0) {
        //check if we assume an array
        if(typeof path[1] === 'number') {
          obj[currentPath] = [];
        } else {
          obj[currentPath] = {};
        }
      }

      return set(obj[currentPath], path.slice(1), value, doNotReplace);
    }

    objectPath.has = function (obj, path) {
      if (typeof path === 'number') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,6 +112,10 @@
       }
       var currentPath = path[0];
       var currentValue = getShallowProperty(obj, currentPath);
+      if (options.includeInheritedProps && (currentPath === '__proto__' ||
+        (currentPath === 'constructor' && typeof currentValue === 'function'))) {
+        throw new Error('For security reasons, object\'s magic properties cannot be set')
+      }
       if (path.length === 1) {
         if (currentValue === void 0 || !doNotReplace) {
           obj[currentPath] = value;
```
