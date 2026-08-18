# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 1105_7
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_7`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-12 of the vulnerable file.

{
  "compilerOptions": {
    /* Basic Options */
    "target": "es5",                        /* Specify ECMAScript target version: 'ES3' (default), 'ES5', 'ES2015', 'ES2016', 'ES2017', 'ES2018', 'ES2019' or 'ESNEXT'. */
    "module": "commonjs",                   /* Specify module code generation: 'none', 'commonjs', 'amd', 'system', 'umd', 'es2015', or 'ESNext'. */
    "lib": ["es2017", "dom"],               /* Specify library files to be included in the compilation. */
    "sourceMap": true,                     /* Generates corresponding '.map' file. */
    "downlevelIteration": true,             /* Provide full support for iterables in 'for-of', spread, and destructuring when targeting 'ES5' or 'ES3'. */
    "strict": true,                         /* Enable all strict type-checking options. */
    "esModuleInterop": true                 /* Enables emit interoperability between CommonJS and ES Modules via creation of namespace objects for all imports. Implies 'allowSyntheticDefaultImports'. */
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,9 @@
     "sourceMap": true,                     /* Generates corresponding '.map' file. */
     "downlevelIteration": true,             /* Provide full support for iterables in 'for-of', spread, and destructuring when targeting 'ES5' or 'ES3'. */
     "strict": true,                         /* Enable all strict type-checking options. */
-    "esModuleInterop": true                 /* Enables emit interoperability between CommonJS and ES Modules via creation of namespace objects for all imports. Implies 'allowSyntheticDefaultImports'. */
+    "esModuleInterop": true,                 /* Enables emit interoperability between CommonJS and ES Modules via creation of namespace objects for all imports. Implies 'allowSyntheticDefaultImports'. */
+    "plugins": [
+      { "name": "typescript-tslint-plugin" }
+    ]
   }
 }
```
