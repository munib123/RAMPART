# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 642_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `642_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

'use strict'

const Buffer = require('safe-buffer').Buffer

const test = require('tap').test

const ssri = require('..')

test('toString()', t => {
  const sri = ssri.parse('sha512-foo sha256-bar!')
  t.equal(
    sri.toString(),
    'sha512-foo sha256-bar!',
    'integrity objects from ssri.parse() can use toString()'
  )
  t.equal(
    sri.toString({strict: true}),
    'sha512-foo',
    'accepts strict mode option'
  )
  t.equal(
    sri.toString({sep: '\n'}),
    'sha512-foo\nsha256-bar!',
    'accepts separator option'
  )
  t.done()
})

test('toJSON()', t => {
  const sri = ssri.parse('sha512-foo sha256-bar!')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,20 +7,20 @@
 const ssri = require('..')
 
 test('toString()', t => {
-  const sri = ssri.parse('sha512-foo sha256-bar!')
+  const sri = ssri.parse('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=')
   t.equal(
     sri.toString(),
-    'sha512-foo sha256-bar!',
+    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
     'integrity objects from ssri.parse() can use toString()'
   )
   t.equal(
     sri.toString({strict: true}),
-    'sha512-foo',
+    'sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
     'accepts strict mode option'
   )
   t.equal(
     sri.toString({sep: '\n'}),
-    'sha512-foo\nsha256-bar!',
+    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=\nsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
     'accepts separator option'
   )
   t.done()
@@ -72,9 +72,12 @@
     'sha512-foo sha512-quux sha1-bar sha1-baz',
     'preserves relative order for algorithms between different concatenations'
   )
+  const strictSri = ssri.parse('sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==')
   t.equal(
-    sri.concat('sha1-bar!', {strict: true}).toString(),
-    'sha512-foo',
+    strictSri.concat('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=', {
+      strict: true
+    }).toString(),
+    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==',
     'accepts strict mode option'
   )
   t.done()
```
