# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2477_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2477_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 41-82 of the vulnerable file.

    debug(config);
    for (const configProperty in configuration) {
        if (!configuration.hasOwnProperty(configProperty)) {
            continue;
        }
        Object.assign(configuration[configProperty], config[configProperty] || {});
    }
}
exports.applyConfigFile = applyConfigFile;
function applyCommandArgs(configuration, argv) {
    if (!argv || !argv.length) {
        return;
    }
    argv = argv.slice(2);
    const parsedArgv = yargs(argv);
    const argvKeys = Object.keys(parsedArgv);
    if (!argvKeys.length) {
        return;
    }
    debug("Appling command arguments:", parsedArgv);
    if (parsedArgv.config) {
        const configFile = path.resolve(process.cwd(), parsedArgv.config);
        applyConfigFile(configuration, configFile);
    }
    for (const key in parsedArgv) {
        if (!parsedArgv.hasOwnProperty(key)) {
            continue;
        }
        const configKey = key
            .replace(/_/g, ".");
        debug(`Found config value from cmd args '${key}' to '${configKey}'`);
        setDeepProperty(configuration, configKey, parsedArgv[key]);
    }
}
exports.applyCommandArgs = applyCommandArgs;
function setDeepProperty(obj, propertyPath, value) {
    const a = splitPath(propertyPath);
    const n = a.length;
    for (let i = 0; i < n - 1; i++) {
        const k = a[i];
        if (!(k in obj)) {
            obj[k] = {};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,12 +58,22 @@
         return;
     }
     debug("Appling command arguments:", parsedArgv);
-    if (parsedArgv.config) {
-        const configFile = path.resolve(process.cwd(), parsedArgv.config);
+    const CONFIG_PROP = 'config';
+    if (parsedArgv[CONFIG_PROP]) {
+        const configFile = path.resolve(process.cwd(), parsedArgv[CONFIG_PROP]);
         applyConfigFile(configuration, configFile);
     }
     for (const key in parsedArgv) {
         if (!parsedArgv.hasOwnProperty(key)) {
+            continue;
+        }
+        if (key.startsWith('_')) {
+            continue;
+        }
+        if (key.endsWith('_')) {
+            continue;
+        }
+        if (key === CONFIG_PROP) {
             continue;
         }
         const configKey = key
@@ -74,19 +84,37 @@
 }
 exports.applyCommandArgs = applyCommandArgs;
 function setDeepProperty(obj, propertyPath, value) {
-    const a = splitPath(propertyPath);
-    const n = a.length;
-    for (let i = 0; i < n - 1; i++) {
-        const k = a[i];
-        if (!(k in obj)) {
-            obj[k] = {};
+    if (!obj) {
+        throw new Error("Invalid object");
+    }
+    if (!propertyPath) {
+        throw new Error("Invalid property path");
+    }
+    const pathParts = splitPath(propertyPath);
+    const pathPartsLen = pathParts.length;
+    for (let i = 0; i < pathPartsLen - 1; i++) {
+        const pathPart = pathParts[i];
+        if (!(pathPart in obj)) {
+            setProp(obj, pathPart, {});
         }
-        obj = obj[k];
+        obj = getProp(obj, pathPart);
     }
-    obj[a[n - 1]] = value;
+    setProp(obj, pathParts[pathPartsLen - 1], value);
     return;
 }
 exports.setDeepProperty = setDeepProperty;
+function setProp(obj, property, value) {
+    if (!obj.hasOwnProperty(property)) {
+        throw new Error(`Property '${property}' is not valid`);
+    }
+    obj[property] = value;
+}
+function getProp(obj, property) {
+    if (!obj.hasOwnProperty(property)) {
+        throw new Error(`Property '${property}' is not valid`);
+    }
+    return obj[property];
+}
 function getDeepProperty(obj, propertyPath) {
     let ret = obj;
     const a = splitPath(propertyPath);
```
