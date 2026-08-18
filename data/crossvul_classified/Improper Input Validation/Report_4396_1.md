# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4396_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4396_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 2016-2038 of the vulnerable file.

        directory: '/@example.com/some/directory',
        filename: 'file.html',
        suffix: 'html',
        hash: '#fragment',
        search: '?query=string',
        host: 'attacker.com',
        hostname: 'attacker.com'
      },
      is: {
        urn: false,
        url: true,
        relative: false,
        name: true,
        sld: false,
        ip: false,
        ip4: false,
        ip6: false,
        idn: false,
        punycode: false
      }
    }
];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2033,6 +2033,55 @@
         idn: false,
         punycode: false
       }
+    }, {
+      name: 'backslashes authority, no ending slash',
+      url: 'https://attacker.com\\@example.com',
+      _url: 'https://attacker.com/@example.com',
+      parts: {
+        protocol: 'https',
+        username: null,
+        password: null,
+        hostname: 'attacker.com',
+        port: null,
+        path: '/@example.com',
+        query: null,
+        fragment: null
+      },
+      accessors: {
+        protocol: 'https',
+        username: '',
+        password: '',
+        port: '',
+        path: '/@example.com',
+        query: '',
+        fragment: '',
+        resource: '/@example.com',
+        authority: 'attacker.com',
+        origin: 'https://attacker.com',
+        userinfo: '',
+        subdomain: '',
+        domain: 'attacker.com',
+        tld: 'com',
+        directory: '/',
+        filename: '@example.com',
+        suffix: 'com',
+        hash: '',
+        search: '',
+        host: 'attacker.com',
+        hostname: 'attacker.com'
+      },
+      is: {
+        urn: false,
+        url: true,
+        relative: false,
+        name: true,
+        sld: false,
+        ip: false,
+        ip4: false,
+        ip6: false,
+        idn: false,
+        punycode: false
+      }
     }
 ];
 
```
