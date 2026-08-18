# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 773_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `773_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 455-495 of the vulnerable file.

                error,
                user,
                users[user] ? users[user].groups : [],
                users[user] ? users[user].acl : JSON.parse(JSON.stringify(defaultAcl.acl))
            );
        });
    });
}

function sanitizePath(id, name, callback) {
    if (name[0] === '/') name = name.substring(1);

    if (!id) {
        if (typeof callback === 'function') {
            callback('Empty ID');
        }
        return;
    }

    if (id) {
        id = id.replace(/\.\./g, ''); // do not allow to write in parent directories
    }

    if (name.indexOf('..') !== -1) {
        name = path.normalize(name);
        name = name.replace(/\\/g, '/');
    }
    if (name[0] === '/') name = name.substring(1); // do not allow absolute paths

    return {id: id, name: name};
}

function checkObject(obj, options, flag) {
    // read rights of object
    if (!obj || !obj.common || !obj.acl || flag === ACCESS_LIST) {
        return true;
    }

    if (options.user === SYSTEM_ADMIN_USER) {
        return true;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -472,11 +472,17 @@
     }
 
     if (id) {
-        id = id.replace(/\.\./g, ''); // do not allow to write in parent directories
-    }
-
-    if (name.indexOf('..') !== -1) {
-        name = path.normalize(name);
+        id = id.replace(/[\]\[*,;'"`<>\\?\/]/g, ''); // remove all invalid characters from states plus slashes
+    }
+
+    if (name.includes('..')) {
+        name = path.normalize('/' + name);
+        name = name.replace(/\\/g, '/');
+    }
+    if (name.includes('..')) {
+        // Also after normalization we still have .. in it - should not happen if normalize worked correctly
+        name = name.replace(/\.\./g, '');
+        name = path.normalize('/' + name);
         name = name.replace(/\\/g, '/');
     }
     if (name[0] === '/') name = name.substring(1); // do not allow absolute paths
```
