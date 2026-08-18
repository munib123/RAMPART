# CrossVul Fix Pair: Insufficiently Protected Credentials in javascript
**Pair ID:** 4559_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4559_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```javascript
Lines 151-182 of the vulnerable file.

  }
  return origin;
}

function trim(options, key) {
  var trimmed = extend(options);
  if (options[key]) {
    trimmed[key] = options[key].trim();
  }
  return trimmed;
}

function trimMultiple(options, keys) {
  return keys.reduce(trim, options);
}

function trimUserDetails(options) {
  return trimMultiple(options, ['username', 'email', 'phoneNumber']);
}

export default {
  toSnakeCase: toSnakeCase,
  toCamelCase: toCamelCase,
  blacklist: blacklist,
  merge: merge,
  pick: pick,
  getKeysNotIn: getKeysNotIn,
  extend: extend,
  getOriginFromUrl: getOriginFromUrl,
  getLocationFromUrl: getLocationFromUrl,
  trimUserDetails: trimUserDetails
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,6 +168,28 @@
   return trimMultiple(options, ['username', 'email', 'phoneNumber']);
 }
 
+/**
+ * Updates the value of a property on the given object, using a deep path selector.
+ * @param {object} obj The object to set the property value on
+ * @param {string|array} path The path to the property that should have its value updated. e.g. 'prop1.prop2.prop3' or ['prop1', 'prop2', 'prop3']
+ * @param {any} value The value to set
+ */
+function updatePropertyOn(obj, path, value) {
+  if (typeof path === 'string') {
+    path = path.split('.');
+  }
+
+  var next = path[0];
+
+  if (obj.hasOwnProperty(next)) {
+    if (path.length === 1) {
+      obj[next] = value;
+    } else {
+      updatePropertyOn(obj[next], path.slice(1), value);
+    }
+  }
+}
+
 export default {
   toSnakeCase: toSnakeCase,
   toCamelCase: toCamelCase,
@@ -178,5 +200,6 @@
   extend: extend,
   getOriginFromUrl: getOriginFromUrl,
   getLocationFromUrl: getLocationFromUrl,
-  trimUserDetails: trimUserDetails
+  trimUserDetails: trimUserDetails,
+  updatePropertyOn: updatePropertyOn
 };
```
