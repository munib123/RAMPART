# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 1105_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "slp-validate",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "@protobufjs/aspromise": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/@protobufjs/aspromise/-/aspromise-1.1.2.tgz",
      "integrity": "sha1-m4sMxmPWaafY9vXQiToU00jzD78=",
      "dev": true
    },
    "@protobufjs/base64": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/@protobufjs/base64/-/base64-1.1.2.tgz",
      "integrity": "sha512-AZkcAA5vnN/v4PDqKyMR5lx7hZttPDgClv83E//FMNhR2TMcLUhfRUBHCmSl0oi9zMgDDqRUJkSxO3wm85+XLg==",
      "dev": true
    },
    "@protobufjs/codegen": {
      "version": "2.0.4",
      "resolved": "https://registry.npmjs.org/@protobufjs/codegen/-/codegen-2.0.4.tgz",
      "integrity": "sha512-YyFaikqM5sH0ziFZCN3xDC7zeGaB/d0IUb9CATugHWbd1FRFwWwt4ld4OYMPWu5a3Xe01mGAULCdqhMlPl29Jg==",
      "dev": true
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "slp-validate",
-  "version": "1.0.0",
+  "version": "1.0.1",
   "lockfileVersion": 1,
   "requires": true,
   "dependencies": {
@@ -763,6 +763,12 @@
       "integrity": "sha512-mBBwmeGTrxEMO4pMaaf/uUEFHnYtwr8FTe8Y/mer4rcV/bye0qGm6pw1bGZFGStxC5O76c5ZAVBGnqHmOaJpdQ==",
       "dev": true
     },
+    "get-caller-file": {
+      "version": "1.0.3",
+      "resolved": "https://registry.npmjs.org/get-caller-file/-/get-caller-file-1.0.3.tgz",
+      "integrity": "sha512-3t6rVToeoZfYSGd8YoLFR2DJkiQrIiUrGcjvFX2mDw3bn6k2OtwHN0TNCLbBO+w8qTvimhDkv+LSscbJY1vE6w==",
+      "dev": true
+    },
     "glob": {
       "version": "7.1.2",
       "resolved": "https://registry.npmjs.org/glob/-/glob-7.1.2.tgz",
@@ -2095,6 +2101,16 @@
         "supports-color": "5.4.0"
       }
     },
+    "mock-require": {
+      "version": "3.0.3",
+      "resolved": "https://registry.npmjs.org/mock-require/-/mock-require-3.0.3.tgz",
+      "integrity": "sha512-lLzfLHcyc10MKQnNUCv7dMcoY/2Qxd6wJfbqCcVk3LDb8An4hF6ohk5AztrvgKhJCqj36uyzi/p5se+tvyD+Wg==",
+      "dev": true,
+      "requires": {
+        "get-caller-file": "^1.0.2",
+        "normalize-path": "^2.1.1"
+      }
+    },
     "module-deps": {
       "version": "6.2.1",
       "resolved": "https://registry.npmjs.org/module-deps/-/module-deps-6.2.1.tgz",
@@ -2129,6 +2145,15 @@
       "resolved": "https://registry.npmjs.org/nan/-/nan-2.14.0.tgz",
       "integrity": "sha512-INOFj37C7k3AfaNTtX8RhsTw7qRy7eLET14cROi9+5HAVbbHuIWUHEauBv5qT4Av2tWasiTY1Jw6puUNqRJXQg==",
       "dev": true
+    },
+    "normalize-path": {
+      "version": "2.1.1",
+      "resolved": "https://registry.npmjs.org/normalize-path/-/normalize-path-2.1.1.tgz",
+      "integrity": "sha1-GrKLVW4Zg2Oowab35vogE3/mrtk=",
+      "dev": true,
+      "requires": {
+        "remove-trailing-separator": "^1.0.1"
+      }
     },
     "number-is-nan": {
       "version": "1.0.1",
@@ -2377,6 +2402,12 @@
         }
       }
     },
+    "remove-trailing-separator": {
+      "version": "1.1.0",
+      "resolved": "https://registry.npmjs.org/remove-trailing-separator/-/remove-trailing-separator-1.1.0.tgz",
+      "integrity": "sha1-wkvOKig62tW8P1jg1IJJuSN52O8=",
+      "dev": true
+    },
     "resolve": {
       "version": "1.12.0",
       "resolved": "https://registry.npmjs.org/resolve/-/resolve-1.12.0.tgz",
@@ -2601,6 +2632,23 @@
       "integrity": "sha1-hnrHTjhkGHsdPUfZlqeOxciDB3c=",
       "dev": true
     },
+    "typescript": {
+      "version": "3.6.4",
+      "resolved": "https://registry.npmjs.org/typescript/-/typescript-3.6.4.tgz",
+      "integrity": "sha512-unoCll1+l+YK4i4F8f22TaNVPRHcD9PA3yCuZ8g5e0qGqlVlJ/8FSateOLLSagn+Yg5+ZwuPkL8LFUc0Jcvksg==",
+      "dev": true
+    },
+    "typescript-tslint-plugin": {
+      "version": "0.5.4",
+      "resolved": "https://registry.npmjs.org/typescript-tslint-plugin/-/typescript-tslint-plugin-0.5.4.tgz",
+      "integrity": "sha512-CQEfGC+p0SoBARI4N2LrGsWJsp4/OE+uKZ68xsWYKHWqMFq4DFQHqOVlK0deEricSN01NmDTqjap63Pw/DHieg==",
+      "dev": true,
+      "requires": {
+        "minimatch": "^3.0.4",
+        "mock-require": "^3.0.2",
+        "vscode-languageserver": "^5.1.0"
+      }
+    },
     "uglify-es": {
       "version": "3.3.9",
       "resolved": "https://registry.npmjs.org/uglify-es/-/uglify-es-3.3.9.tgz",
@@ -2691,6 +2739,44 @@
       "integrity": "sha512-iq+S7vZJE60yejDYM0ek6zg308+UZsdtPExWP9VZoCFCz1zkJoXFnAX7aZfd/ZwrkidzdUZL0C/ryW+JwAiIGw==",
       "dev": true
     },
+    "vscode-jsonrpc": {
+      "version": "4.0.0",
+      "resolved": "https://registry.npmjs.org/vscode-jsonrpc/-/vscode-jsonrpc-4.0.0.tgz",
+      "integrity": "sha512-perEnXQdQOJMTDFNv+UF3h1Y0z4iSiaN9jIlb0OqIYgosPCZGYh/MCUlkFtV2668PL69lRDO32hmvL2yiidUYg==",
+      "dev": true
+    },
+    "vscode-languageserver": {
+      "version": "5.2.1",
+      "resolved": "https://registry.npmjs.org/vscode-languageserver/-/vscode-languageserver-5.2.1.tgz",
+      "integrity": "sha512-GuayqdKZqAwwaCUjDvMTAVRPJOp/SLON3mJ07eGsx/Iq9HjRymhKWztX41rISqDKhHVVyFM+IywICyZDla6U3A==",
+      "dev": true,
+      "requires": {
+        "vscode-languageserver-protocol": "3.14.1",
+        "vscode-uri": "^1.0.6"
+      }
+    },
+    "vscode-languageserver-protocol": {
+      "version": "3.14.1",
+      "resolved": "https://registry.npmjs.org/vscode-languageserver-protocol/-/vscode-languageserver-protocol-3.14.1.tgz",
+      "integrity": "sha512-IL66BLb2g20uIKog5Y2dQ0IiigW0XKrvmWiOvc0yXw80z3tMEzEnHjaGAb3ENuU7MnQqgnYJ1Cl2l9RvNgDi4g==",
+      "dev": true,
+      "requires": {
+        "vscode-jsonrpc": "^4.0.0",
+        "vscode-languageserver-types": "3.14.0"
+      }
+    },
+    "vscode-languageserver-types": {
+      "version": "3.14.0",
+      "resolved": "https://registry.npmjs.org/vscode-languageserver-types/-/vscode-languageserver-types-3.14.0.tgz",
+      "integrity": "sha512-lTmS6AlAlMHOvPQemVwo3CezxBp0sNB95KNPkqp3Nxd5VFEnuG1ByM0zlRWos0zjO3ZWtkvhal0COgiV1xIA4A==",
+      "dev": true
+    },
+    "vscode-uri": {
+      "version": "1.0.8",
+      "resolved": "https://registry.npmjs.org/vscode-uri/-/vscode-uri-1.0.8.tgz",
+      "integrity": "sha512-obtSWTlbJ+a+TFRYGaUumtVwb+InIUVI0Lu0VBUAPmj2cU5JutEXg3xUE0c2J5Tcy7h2DEKVJBFi+Y9ZSFzzPQ==",
+      "dev": true
+    },
     "window-size": {
       "version": "0.1.4",
       "resolved": "https://registry.npmjs.org/window-size/-/window-size-0.1.4.tgz",
```
