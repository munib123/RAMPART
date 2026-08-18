# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 562_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `562_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 12-52 of the vulnerable file.

describe('resolvePath(relativePath)', function () {
  describe('arguments', function () {
    describe('relativePath', function () {
      it('should be required', function () {
        assert.throws(resolvePath.bind(null, undefined),
          /argument relativePath is required/)
      })

      it('should reject non-strings', function () {
        assert.throws(resolvePath.bind(null, 42),
          /argument relativePath must be a string/)
        assert.throws(resolvePath.bind(null, {}),
          /argument relativePath must be a string/)
        assert.throws(resolvePath.bind(null, []),
          /argument relativePath must be a string/)
      })

      it('should resolve relative to cwd', function () {
        assert.equal(normalize(resolvePath('index.js')),
          normalize(join(process.cwd(), 'index.js')))
      })

      it('should accept empty string', function () {
        assert.equal(normalize(resolvePath('')),
          normalize(process.cwd()))
      })
    })
  })

  describe('when relativePath is absolute', function () {
    it('should throw Malicious Path error', function () {
      assert.throws(resolvePath.bind(null, join(__dirname, sep)),
        expectError(400, 'Malicious Path'))
    })
  })

  describe('when relativePath contains a NULL byte', function () {
    it('should throw Malicious Path error', function () {
      assert.throws(resolvePath.bind(null, 'hi\0there'),
        expectError(400, 'Malicious Path'))
    })
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,11 @@
       it('should resolve relative to cwd', function () {
         assert.equal(normalize(resolvePath('index.js')),
           normalize(join(process.cwd(), 'index.js')))
+      })
+
+      it('should resolve relative with special characters', function () {
+        assert.equal(normalize(resolvePath('f:oo$bar')),
+          normalize(join(process.cwd(), './f:oo$bar')))
       })
 
       it('should accept empty string', function () {
@@ -87,6 +92,11 @@
       it('should resolve relative to rootPath', function () {
         assert.equal(normalize(resolvePath(__dirname, 'index.js')),
           normalize(resolve(__dirname, 'index.js')))
+      })
+
+      it('should resolve relative to rootPath with special characters', function () {
+        assert.equal(normalize(resolvePath(__dirname, 'f:oo$bar')),
+        normalize(resolve(__dirname, './f:oo$bar')))
       })
 
       it('should accept relative path', function () {
```
