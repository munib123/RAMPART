# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 642_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `642_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 91-116 of the vulnerable file.

      // Must be valid base64
      digest: 'wut!!!??!!??!'
    }, {
      algorithm: 'sha256',
      digest: hash(TEST_DATA, 'sha256'),
      options: ['foo']
    }],
    'sha512': [{
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
      // Options must use VCHAR
      options: ['\x01']
    }]
  }
  t.equal(
    ssri.stringify(sriLike, {strict: true}),
    `sha256-${hash(TEST_DATA, 'sha256')}?foo`,
    'entries that do not conform to strict spec interpretation removed'
  )
  t.equal(
    ssri.stringify('sha512-foo sha256-bar', {sep: ' \r|\n\t', strict: true}),
    'sha512-foo \r \n\tsha256-bar',
    'strict mode replaces non-whitespace characters in separator with space'
  )
  t.done()
})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,8 +108,8 @@
     'entries that do not conform to strict spec interpretation removed'
   )
   t.equal(
-    ssri.stringify('sha512-foo sha256-bar', {sep: ' \r|\n\t', strict: true}),
-    'sha512-foo \r \n\tsha256-bar',
+    ssri.stringify('sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=', {sep: ' \r|\n\t', strict: true}),
+    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== \r \n\tsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
     'strict mode replaces non-whitespace characters in separator with space'
   )
   t.done()
```
