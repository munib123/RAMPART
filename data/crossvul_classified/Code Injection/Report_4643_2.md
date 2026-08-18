# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 129-158 of the vulnerable file.

        if (this.headerChunks) {
            let chunk = Buffer.concat(this.headerChunks, this.headerBytes);
            this.bodySize += chunk.length;
            this.push(chunk);
            this.headerChunks = null;
        }
        callback();
    }

    parseHeaders() {
        let lines = (this.rawHeaders || '').toString().split(/\r?\n/);
        for (let i = lines.length - 1; i > 0; i--) {
            if (/^\s/.test(lines[i])) {
                lines[i - 1] += '\n' + lines[i];
                lines.splice(i, 1);
            }
        }
        return lines
            .filter(line => line.trim())
            .map(line => ({
                key: line
                    .substr(0, line.indexOf(':'))
                    .trim()
                    .toLowerCase(),
                line
            }));
    }
}

module.exports = MessageParser;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,10 +146,7 @@
         return lines
             .filter(line => line.trim())
             .map(line => ({
-                key: line
-                    .substr(0, line.indexOf(':'))
-                    .trim()
-                    .toLowerCase(),
+                key: line.substr(0, line.indexOf(':')).trim().toLowerCase(),
                 line
             }));
     }
```
