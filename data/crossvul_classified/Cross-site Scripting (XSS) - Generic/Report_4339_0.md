# CrossVul Fix Pair: Improper Encoding or Escaping of Output in javascript
**Pair ID:** 4339_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4339_0`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```javascript
Lines 1-17 of the vulnerable file.

const {escapeRegExp, size, isString} = require('lodash');
const {SECRET_REPLACEMENT, SECRET_MIN_SIZE} = require('./definitions/constants');

module.exports = (env) => {
  const toReplace = Object.keys(env).filter((envVar) => {
    // https://github.com/semantic-release/semantic-release/issues/1558
    if (envVar === 'GOPRIVATE') {
      return false;
    }

    return /token|password|credential|secret|private/i.test(envVar) && size(env[envVar].trim()) >= SECRET_MIN_SIZE;
  });

  const regexp = new RegExp(toReplace.map((envVar) => escapeRegExp(env[envVar])).join('|'), 'g');
  return (output) =>
    output && isString(output) && toReplace.length > 0 ? output.toString().replace(regexp, SECRET_REPLACEMENT) : output;
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,12 @@
     return /token|password|credential|secret|private/i.test(envVar) && size(env[envVar].trim()) >= SECRET_MIN_SIZE;
   });
 
-  const regexp = new RegExp(toReplace.map((envVar) => escapeRegExp(env[envVar])).join('|'), 'g');
+  const regexp = new RegExp(
+    toReplace
+      .map((envVar) => `${escapeRegExp(env[envVar])}|${encodeURI(escapeRegExp(env[envVar]))}`)
+      .join('|'),
+    'g'
+  );
   return (output) =>
     output && isString(output) && toReplace.length > 0 ? output.toString().replace(regexp, SECRET_REPLACEMENT) : output;
 };
```
