# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1949_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1949_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 4-42 of the vulnerable file.

const { buildURL } = require('../lib/utils')

test('should produce valid URL', (t) => {
  t.plan(1)
  const url = buildURL('/hi', 'http://localhost')
  t.equal(url.href, 'http://localhost/hi')
})

test('should produce valid URL', (t) => {
  t.plan(1)
  const url = buildURL('http://localhost/hi', 'http://localhost')
  t.equal(url.href, 'http://localhost/hi')
})

test('should return same source when base is not specified', (t) => {
  t.plan(1)
  const url = buildURL('http://localhost/hi')
  t.equal(url.href, 'http://localhost/hi')
})

const errorInputs = [
  { source: '//10.0.0.10/hi', base: 'http://localhost' },
  { source: 'http://10.0.0.10/hi', base: 'http://localhost' },
  { source: 'https://10.0.0.10/hi', base: 'http://localhost' },
  { source: 'blah://10.0.0.10/hi', base: 'http://localhost' },
  { source: '//httpbin.org/hi', base: 'http://localhost' },
  { source: 'urn:foo:bar', base: 'http://localhost' }
]

test('should throw when trying to override base', (t) => {
  t.plan(errorInputs.length)

  errorInputs.forEach(({ source, base }) => {
    t.test(source, (t) => {
      t.plan(1)
      t.throws(() => buildURL(source, base))
    })
  })
})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,13 +21,31 @@
   t.equal(url.href, 'http://localhost/hi')
 })
 
+test('should handle lack of trailing slash in base', (t) => {
+  t.plan(3)
+  let url = buildURL('hi', 'http://localhost/hi')
+  t.equal(url.href, 'http://localhost/hi')
+
+  url = buildURL('hi/', 'http://localhost/hi')
+  t.equal(url.href, 'http://localhost/hi/')
+
+  url = buildURL('hi/more', 'http://localhost/hi')
+  t.equal(url.href, 'http://localhost/hi/more')
+})
+
 const errorInputs = [
   { source: '//10.0.0.10/hi', base: 'http://localhost' },
   { source: 'http://10.0.0.10/hi', base: 'http://localhost' },
   { source: 'https://10.0.0.10/hi', base: 'http://localhost' },
   { source: 'blah://10.0.0.10/hi', base: 'http://localhost' },
   { source: '//httpbin.org/hi', base: 'http://localhost' },
-  { source: 'urn:foo:bar', base: 'http://localhost' }
+  { source: 'urn:foo:bar', base: 'http://localhost' },
+  { source: 'http://localhost/private', base: 'http://localhost/exposed/' },
+  { source: 'http://localhost/exposed-extra', base: 'http://localhost/exposed' },
+  { source: '/private', base: 'http://localhost/exposed/' },
+  { source: '/exposed-extra', base: 'http://localhost/exposed' },
+  { source: '../private', base: 'http://localhost/exposed/' },
+  { source: 'exposed-extra', base: 'http://localhost/exposed' }
 ]
 
 test('should throw when trying to override base', (t) => {
```
