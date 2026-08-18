# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4546_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4546_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 23-51 of the vulnerable file.

        })
      })
    })
  })

  Object.keys(regexes).forEach(function (parser) {
    suite(`no reverse lookup in ${parser}`, function () {
      regexes[parser].forEach(function(item) {
        test(item.regex, function () {
          if (/\(\?<[!=]/.test(item.regex)) {
            assert.ok(false, 'go parser does not support regex lookbehind. See https://github.com/google/re2/wiki/Syntax')
          }
          if (/\(\?[!=]/.test(item.regex)) {
            assert.ok(false, 'go parser does not support regex lookahead. See https://github.com/google/re2/wiki/Syntax')
          }
        })
      })
    })
  })

  test('should not backtrack', function () {
    var parse = refImpl(regexes).parse
    var ua = Array(3200).fill('a').join('')
    var start = Date.now()
    parse(ua)
    var diff = Date.now() - start
    assert.ok(diff < 500, diff)
  })
})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,12 +40,50 @@
     })
   })
 
-  test('should not backtrack', function () {
-    var parse = refImpl(regexes).parse
-    var ua = Array(3200).fill('a').join('')
+})
+
+suite('redos', function () {
+  var parse = refImpl(regexes).parse
+
+  function timer () {
     var start = Date.now()
+    return function () {
+      return Date.now() - start
+    }
+  }
+
+  function testRedos (ua) {
+    var time = timer()
     parse(ua)
-    var diff = Date.now() - start
-    assert.ok(diff < 500, diff)
+    var diff = time()
+    assert.ok(diff < 300, diff)
+  }
+
+  test('should not backtrack aaaa..', function () {
+    testRedos(Array(3200).fill('a').join(''))
+  })
+
+  test('should not backtrack Smartwatch', function () {
+    testRedos('SmartWatch(' + Array(3500).fill(' ').join('') + 'z')
+  })
+
+  test('should not backtrack HuaweiA', function () {
+    testRedos(';A Build HuaweiA' + Array(3500).fill('4').join('') + 'z')
+  })
+
+  test('should not backtrack HbbTV LGE', function () {
+    testRedos('HbbTV/0.0.0 (;LGE;' + Array(3500).fill(' ').join('') + 'z')
+  })
+
+  test('should not backtrack HbbTV CUS', function () {
+    testRedos('HbbTV/0.0.0 (;CUS:;' + Array(3500).fill(' ').join('') + 'z')
+  })
+
+  test('should not backtrack HbbTV', function () {
+    testRedos('HbbTV/0.0.0 (;' + Array(3500).fill(' ').join('') + 'z')
+  })
+
+  test('should not backtrack HbbTV z', function () {
+    testRedos('HbbTV/0.0.0 (;z;' + Array(3500).fill(' ').join('') + 'z')
   })
 })
```
