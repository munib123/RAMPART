# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in json
**Pair ID:** 782_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `782_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "compile-sass",
  "version": "1.0.4",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "@babel/code-frame": {
      "version": "7.8.3",
      "resolved": "https://registry.npmjs.org/@babel/code-frame/-/code-frame-7.8.3.tgz",
      "integrity": "sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==",
      "dev": true,
      "requires": {
        "@babel/highlight": "^7.8.3"
      }
    },
    "@babel/core": {
      "version": "7.8.4",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.8.4.tgz",
      "integrity": "sha512-0LiLrB2PwrVI+a2/IEskBopDYSd8BCb3rOvH7D5tzoWd696TBEduBvuLVm4Nx6rltrLZqvI3MCalB2K2aVzQjA==",
      "dev": true,
      "requires": {
        "@babel/code-frame": "^7.8.3",
        "@babel/generator": "^7.8.4",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "compile-sass",
-  "version": "1.0.4",
+  "version": "1.0.5",
   "lockfileVersion": 1,
   "requires": true,
   "dependencies": {
@@ -589,9 +589,9 @@
       }
     },
     "@types/babel__core": {
-      "version": "7.1.4",
-      "resolved": "https://registry.npmjs.org/@types/babel__core/-/babel__core-7.1.4.tgz",
-      "integrity": "sha512-c/5MuRz5HM4aizqL5ViYfW4iEnmfPcfbH4Xa6GgLT21dMc1NGeNnuS6egHheOmP+kCJ9CAzC4pv4SDCWTnRkbg==",
+      "version": "7.1.5",
+      "resolved": "https://registry.npmjs.org/@types/babel__core/-/babel__core-7.1.5.tgz",
+      "integrity": "sha512-+ckxwNj892FWgvwrUWLOghQ2JDgOgeqTPwrcl+0t1pG59CP8qMJ6S/efmEd999vCFSJKOpyMakvU+w380rduUQ==",
       "dev": true,
       "requires": {
         "@babel/parser": "^7.1.0",
@@ -621,9 +621,9 @@
       }
     },
     "@types/babel__traverse": {
-      "version": "7.0.8",
-      "resolved": "https://registry.npmjs.org/@types/babel__traverse/-/babel__traverse-7.0.8.tgz",
-      "integrity": "sha512-yGeB2dHEdvxjP0y4UbRtQaSkXJ9649fYCmIdRoul5kfAoGCwxuCbMhag0k3RPfnuh9kPGm8x89btcfDEXdVWGw==",
+      "version": "7.0.9",
+      "resolved": "https://registry.npmjs.org/@types/babel__traverse/-/babel__traverse-7.0.9.tgz",
+      "integrity": "sha512-jEFQ8L1tuvPjOI8lnpaf73oCJe+aoxL6ygqSy6c8LcW98zaC+4mzWuQIRCEvKeCOu+lbqdXcg4Uqmm1S8AP1tw==",
       "dev": true,
       "requires": {
         "@babel/types": "^7.3.0"
@@ -673,9 +673,9 @@
       }
     },
     "@types/node": {
-      "version": "12.12.27",
-      "resolved": "https://registry.npmjs.org/@types/node/-/node-12.12.27.tgz",
-      "integrity": "sha512-odQFl/+B9idbdS0e8IxDl2ia/LP8KZLXhV3BUeI98TrZp0uoIzQPhGd+5EtzHmT0SMOIaPd7jfz6pOHLWTtl7A==",
+      "version": "12.12.28",
+      "resolved": "https://registry.npmjs.org/@types/node/-/node-12.12.28.tgz",
+      "integrity": "sha512-g73GJYJDXgf0jqg+P9S8h2acWbDXNkoCX8DLtJVu7Fkn788pzQ/oJsrdJz/2JejRf/SjfZaAhsw+3nd1D5EWGg==",
       "dev": true
     },
     "@types/node-sass": {
@@ -4595,9 +4595,9 @@
       }
     },
     "make-error": {
-      "version": "1.3.5",
-      "resolved": "https://registry.npmjs.org/make-error/-/make-error-1.3.5.tgz",
-      "integrity": "sha512-c3sIjNUow0+8swNwVpqoH4YCShKNFkMaw6oH1mNS2haDZQqkeZFlHS3dhoeEbKKmJB4vXpJucU6oH75aDYeE9g==",
+      "version": "1.3.6",
+      "resolved": "https://registry.npmjs.org/make-error/-/make-error-1.3.6.tgz",
+      "integrity": "sha512-s8UhlNe7vPKomQhC1qFelMokr/Sc3AgNbso3n74mVPA5LTZwkB9NlXf4XPamLxJE8h0gh73rM94xvwRT2CVInw==",
       "dev": true
     },
     "makeerror": {
@@ -6382,9 +6382,9 @@
       }
     },
     "typescript": {
-      "version": "3.7.5",
-      "resolved": "https://registry.npmjs.org/typescript/-/typescript-3.7.5.tgz",
-      "integrity": "sha512-/P5lkRXkWHNAbcJIiHPfRoKqyd7bsyCma1hZNUGfn20qm64T6ZBlrzprymeu918H+mB/0rIg2gGK/BXkhhYgBw==",
+      "version": "3.8.2",
+      "resolved": "https://registry.npmjs.org/typescript/-/typescript-3.8.2.tgz",
+      "integrity": "sha512-EgOVgL/4xfVrCMbhYKUQTdF37SQn4Iw73H5BgCrF1Abdun7Kwy/QZsE/ssAy0y4LxBbvua3PIbFsbRczWWnDdQ==",
       "dev": true
     },
     "union-value": {
```
