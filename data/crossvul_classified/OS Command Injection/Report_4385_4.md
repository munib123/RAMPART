# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4385_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4385_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 504-544 of the vulnerable file.

  for (let i = 0; i <= 2000; i++) {
    if (!(s[i] === undefined ||
      s[i] === '>' ||
      s[i] === '<' ||
      s[i] === '*' ||
      s[i] === '?' ||
      s[i] === '[' ||
      s[i] === ']' ||
      s[i] === '|' ||
      s[i] === '˚' ||
      s[i] === '$' ||
      s[i] === ';' ||
      s[i] === '&' ||
      s[i] === '(' ||
      s[i] === ')' ||
      s[i] === ']' ||
      s[i] === '#' ||
      s[i] === '\\' ||
      s[i] === '\t' ||
      s[i] === '\n' ||
      s[i] === '"')) {
      result = result + s[i];
    }
  }
  return result;
}

function isPrototypePolluted() {
  const s = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
  let notPolluted = true;
  let st = '';

  st.__proto__.replace = stringReplace;
  st.__proto__.toLowerCase = stringToLower;
  st.__proto__.toString = stringToString;
  st.__proto__.substr = stringSubstr;

  notPolluted = notPolluted || !(s.length === 62)
  const ms = Date.now();
  if (typeof ms === 'number' && ms > 1600000000000) {
    const l = ms % 100 + 15;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -521,6 +521,8 @@
       s[i] === '\\' ||
       s[i] === '\t' ||
       s[i] === '\n' ||
+      s[i] === '\'' ||
+      s[i] === '`' ||
       s[i] === '"')) {
       result = result + s[i];
     }
```
