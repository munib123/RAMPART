# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4361_7
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 30-70 of the vulnerable file.

// const _sunos = (_platform === 'sunos');

let _cores = 0;
let wmicPath = '';
let codepage = '';

const execOptsWin = {
  windowsHide: true,
  maxBuffer: 1024 * 20000,
  encoding: 'UTF-8',
  env: util._extend({}, process.env, { LANG: 'en_US.UTF-8' })
};

function toInt(value) {
  let result = parseInt(value, 10);
  if (isNaN(result)) {
    result = 0;
  }
  return result;
}

function isFunction(functionToCheck) {
  let getType = {};
  return functionToCheck && getType.toString.call(functionToCheck) === '[object Function]';
}

function unique(obj) {
  let uniques = [];
  let stringify = {};
  for (let i = 0; i < obj.length; i++) {
    let keys = Object.keys(obj[i]);
    keys.sort(function (a, b) { return a - b; });
    let str = '';
    for (let j = 0; j < keys.length; j++) {
      str += JSON.stringify(keys[j]);
      str += JSON.stringify(obj[i][keys[j]]);
    }
    if (!{}.hasOwnProperty.call(stringify, str)) {
      uniques.push(obj[i]);
      stringify[str] = true;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,13 @@
   }
   return result;
 }
+
+
+const stringReplace = new String().replace;
+const stringToLower = new String().toLowerCase;
+const stringToString = new String().toString;
+const stringSubstr = new String().substr;
+const stringTrim = new String().trim;
 
 function isFunction(functionToCheck) {
   let getType = {};
@@ -523,6 +530,12 @@
   const s = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
   let notPolluted = true;
   let st = '';
+
+  st.__proto__.replace = stringReplace;
+  st.__proto__.toLowerCase = stringToLower;
+  st.__proto__.toString = stringToString;
+  st.__proto__.substr = stringSubstr;
+
   notPolluted = notPolluted || !(s.length === 62)
   const ms = Date.now();
   if (typeof ms === 'number' && ms > 1600000000000) {
@@ -542,6 +555,7 @@
     // string manipulation
     let p = Math.random() * l * 0.9999999999;
     let stm = st.substr(0, p) + ' ' + st.substr(p, 2000);
+    stm.__proto__.replace = stringReplace;
     let sto = stm.replace(/ /g, '');
     notPolluted = notPolluted && st === sto;
     p = Math.random() * l * 0.9999999999;
@@ -562,6 +576,7 @@
     notPolluted = notPolluted && (stl.length === l) && stl[l - 1] && !(stl[l])
     for (let i = 0; i < l; i++) {
       const s1 = st[i];
+      s1.__proto__.toLowerCase = stringToLower;
       const s2 = stl ? stl[i] : '';
       const s1l = s1.toLowerCase();
       notPolluted = notPolluted && s1l[0] === s2 && s1l[0] && !(s1l[1]);
@@ -806,3 +821,8 @@
 exports.sanitizeShellString = sanitizeShellString;
 exports.isPrototypePolluted = isPrototypePolluted;
 exports.decodePiCpuinfo = decodePiCpuinfo;
+exports.stringReplace = stringReplace;
+exports.stringToLower = stringToLower;
+exports.stringToString = stringToString;
+exports.stringSubstr = stringSubstr;
+exports.stringTrim = stringTrim;
```
