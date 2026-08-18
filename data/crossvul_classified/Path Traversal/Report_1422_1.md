# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 1422_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1422_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 82-108 of the vulnerable file.

        "email": "mrgmp2004@hotmail.com"
    },{
        "name": "luoage",
        "email": "luoage@msn.cn"
    },{
        "name": "Mato Holly",
        "email": "mato.holly@gmail.com"
    },{
        "name": "Tema Smirnov",
        "email": "github.tema@smirnov.one"
    }, {
        "name": "Jeroen van Hilst",
        "email": "frunjik@gmail.com"
    }, {
        "name": "Pedro Costa",
        "email": "pedro@pmcdigital.pt"
    }, {
        "name": "Sarp Aykent",
        "email": "shackhers@gmail.com"
    }],
    "version": "3.2.2",
    "homepage": "http://www.totaljs.com",
    "bugs": {
        "url": "https://github.com/totaljs/framework/issues",
        "email": "petersirka@gmail.com"
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
         "name": "Sarp Aykent",
         "email": "shackhers@gmail.com"
     }],
-    "version": "3.2.2",
+    "version": "3.2.3",
     "homepage": "http://www.totaljs.com",
     "bugs": {
         "url": "https://github.com/totaljs/framework/issues",
```
