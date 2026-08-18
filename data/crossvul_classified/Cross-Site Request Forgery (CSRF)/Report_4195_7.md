# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in json
**Pair ID:** 4195_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4195_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "ad-ldap-connector",
  "version": "5.0.12",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "@arcanis/slice-ansi": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/@arcanis/slice-ansi/-/slice-ansi-1.0.2.tgz",
      "integrity": "sha512-lDL63z0W/L/WTgqrwVOuNyMAsTv+pvjybd21z9SWdStmQoXT59E/iVWwat3gYjcdTNBf6oHAMoyFm8dtjpXEYw==",
      "dev": true,
      "requires": {
        "grapheme-splitter": "^1.0.4"
      }
    },
    "@auth0/thumbprint": {
      "version": "0.0.6",
      "resolved": "https://registry.npmjs.org/@auth0/thumbprint/-/thumbprint-0.0.6.tgz",
      "integrity": "sha1-yrEGLGwEZizmxZLUgVfsQmiuhRg="
    },
    "@nodelib/fs.scandir": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/@nodelib/fs.scandir/-/fs.scandir-2.1.3.tgz",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "ad-ldap-connector",
-  "version": "5.0.12",
+  "version": "5.0.13",
   "lockfileVersion": 1,
   "requires": true,
   "dependencies": {
@@ -1771,6 +1771,59 @@
       "resolved": "https://registry.npmjs.org/crypto-random-string/-/crypto-random-string-2.0.0.tgz",
       "integrity": "sha512-v1plID3y9r/lPhviJ1wrXpLeyUIGAZ2SHNYTEapm7/8A9nLPoyvVp3RK/EPFqn5kEznyWgYZNsRtYYIWbuG8KA==",
       "dev": true
+    },
+    "csrf": {
+      "version": "3.0.6",
+      "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/csrf/-/csrf-3.0.6.tgz",
+      "integrity": "sha1-thEg3c7q/JHnbtUxO7XAsmZ7cQo=",
+      "requires": {
+        "rndm": "1.2.0",
+        "tsscmp": "1.0.5",
+        "uid-safe": "2.1.4"
+      },
+      "dependencies": {
+        "uid-safe": {
+          "version": "2.1.4",
+          "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/uid-safe/-/uid-safe-2.1.4.tgz",
+          "integrity": "sha1-Otbzg2jG1MjHXsF2I/t5qh0HHYE=",
+          "requires": {
+            "random-bytes": "~1.0.0"
+          }
+        }
+      }
+    },
+    "csurf": {
+      "version": "1.9.0",
+      "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/csurf/-/csurf-1.9.0.tgz",
+      "integrity": "sha1-SdLGkl/87Ht95VlZfBU/pTM2QTM=",
+      "requires": {
+        "cookie": "0.3.1",
+        "cookie-signature": "1.0.6",
+        "csrf": "~3.0.3",
+        "http-errors": "~1.5.0"
+      },
+      "dependencies": {
+        "http-errors": {
+          "version": "1.5.1",
+          "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/http-errors/-/http-errors-1.5.1.tgz",
+          "integrity": "sha1-eIwNLB3iyBuebowBhDtrl+uSB1A=",
+          "requires": {
+            "inherits": "2.0.3",
+            "setprototypeof": "1.0.2",
+            "statuses": ">= 1.3.1 < 2"
+          }
+        },
+        "inherits": {
+          "version": "2.0.3",
+          "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/inherits/-/inherits-2.0.3.tgz",
+          "integrity": "sha1-Yzwsg+PaQqUC9SRmAiSA9CCCYd4="
+        },
+        "setprototypeof": {
+          "version": "1.0.2",
+          "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/setprototypeof/-/setprototypeof-1.0.2.tgz",
+          "integrity": "sha1-gaVSFB7BBLiOic44MQOtXGZWTQg="
+        }
+      }
     },
     "cycle": {
       "version": "1.0.3",
@@ -4919,6 +4972,11 @@
       "requires": {
         "glob": "^7.0.5"
       }
+    },
+    "rndm": {
+      "version": "1.2.0",
+      "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/rndm/-/rndm-1.2.0.tgz",
+      "integrity": "sha1-8z/pz7Urv9UgqhgyO8ZdsRCht2w="
     },
     "run-async": {
       "version": "2.4.1",
@@ -6651,6 +6709,11 @@
       "integrity": "sha512-i/6DQjL8Xf3be4K/E6Wgpekn5Qasl1usyw++dAA35Ue5orEn65VIxOA+YvNNl9HV3qv70T7CNwjODHZrLwvd1Q==",
       "dev": true
     },
+    "tsscmp": {
+      "version": "1.0.5",
+      "resolved": "https://a0us.jfrog.io/a0us/api/npm/npm/tsscmp/-/tsscmp-1.0.5.tgz",
+      "integrity": "sha1-fcSjOvcVgatDN9qR2FylQn69mpc="
+    },
     "tunnel": {
       "version": "0.0.6",
       "resolved": "https://registry.npmjs.org/tunnel/-/tunnel-0.0.6.tgz",
```
