# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1946_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1946_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 95-135 of the vulnerable file.

require('./tree/color');
require('./tree/directive');
require('./tree/operation');
require('./tree/dimension');
require('./tree/keyword');
require('./tree/variable');
require('./tree/ruleset');
require('./tree/element');
require('./tree/selector');
require('./tree/quoted');
require('./tree/expression');
require('./tree/rule');
require('./tree/call');
require('./tree/url');
require('./tree/alpha');
require('./tree/import');
require('./tree/mixin');
require('./tree/comment');
require('./tree/anonymous');
require('./tree/value');
require('./tree/javascript');
require('./tree/assignment');
require('./tree/condition');
require('./tree/paren');
require('./tree/media');
require('./tree/unicode-descriptor');
require('./tree/negative');
require('./tree/extend');


var isUrlRe = /^(?:https?:)?\/\//i;

less.Parser.fileLoader = function (file, currentFileInfo, callback, env) {
    var pathname, dirname, data,
        newFileInfo = {
            relativeUrls: env.relativeUrls,
            entryPath: currentFileInfo.entryPath,
            rootpath: currentFileInfo.rootpath,
            rootFilename: currentFileInfo.rootFilename
        };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,7 +112,9 @@
 require('./tree/comment');
 require('./tree/anonymous');
 require('./tree/value');
-require('./tree/javascript');
+/* BEGIN MODIFICATION */
+// Removed require('./tree/javascript');
+/* END MODIFICATION */
 require('./tree/assignment');
 require('./tree/condition');
 require('./tree/paren');
```
