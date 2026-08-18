# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 781_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `781_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 82-121 of the vulnerable file.

          res
        );
        if (shallowObj && shallowObj !== res) {
          if ((value && shallowObj === value) || value === undefined) {
            if (value !== undefined) {
              return shallowObj;
            }

            res.push(shallowObj);
          }
        }
      }

      if (res.length === 0) {
        return undefined;
      }

      return res;
    }

    obj = obj[key];
    if (obj === undefined || obj === null) {
      break;
    }
  }

  // if we have a null object, make sure it's the one the user was after,
  // if it's not (i.e. parts has a length) then give undefined back.
  if (obj === null && i !== parts.length - 1) {
    obj = undefined;
  } else if (!star && value) {
    key = path.split('.').pop();
    parent[key] = value;
  }
  return obj;
}

if (typeof module !== 'undefined') {
  module.exports = undefsafe;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,10 @@
       return res;
     }
 
+    if (Object.getOwnPropertyNames(obj).indexOf(key) == -1) {
+      return undefined;
+    }
+
     obj = obj[key];
     if (obj === undefined || obj === null) {
       break;
```
