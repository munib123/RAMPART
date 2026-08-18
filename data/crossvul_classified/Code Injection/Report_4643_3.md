# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 93-136 of the vulnerable file.

            }
        }

        return result;
    }

    /**
     * Parses cookie string from the 'Set-Cookie:' header
     *
     * @param {String} cookieStr String from the 'Set-Cookie:' header
     * @returns {Object} Cookie object
     */
    parse(cookieStr) {
        let cookie = {};

        (cookieStr || '')
            .toString()
            .split(';')
            .forEach(cookiePart => {
                let valueParts = cookiePart.split('=');
                let key = valueParts
                    .shift()
                    .trim()
                    .toLowerCase();
                let value = valueParts.join('=').trim();
                let domain;

                if (!key) {
                    // skip empty parts
                    return;
                }

                switch (key) {
                    case 'expires':
                        value = new Date(value);
                        // ignore date if can not parse it
                        if (value.toString() !== 'Invalid Date') {
                            cookie.expires = value;
                        }
                        break;

                    case 'path':
                        cookie.path = value;
                        break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,10 +110,7 @@
             .split(';')
             .forEach(cookiePart => {
                 let valueParts = cookiePart.split('=');
-                let key = valueParts
-                    .shift()
-                    .trim()
-                    .toLowerCase();
+                let key = valueParts.shift().trim().toLowerCase();
                 let value = valueParts.join('=').trim();
                 let domain;
 
```
