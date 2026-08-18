# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2510_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2510_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 149-189 of the vulnerable file.


  test('support custom escape function in client mode', function () {
    var customEscape;
    var fn;
    var str;
    customEscape = function customEscape(str) {
      return !str ? '' : str.toUpperCase();
    };
    fn = ejs.compile('HELLO <%= name %>', {escape: customEscape, client: true});
    str = fn.toString();
    if (!process.env.running_under_istanbul) {
      eval('var preFn = ' + str);
      assert.equal(preFn({name: 'world'}), 'HELLO WORLD'); // eslint-disable-line no-undef
    }
  });

  test('strict mode works', function () {
    assert.equal(ejs.render(fixture('strict.ejs'), {}, {strict: true}), 'true');
  });

});

suite('ejs.render(str, data, opts)', function () {
  test('render the template', function () {
    assert.equal(ejs.render('<p>yay</p>'), '<p>yay</p>');
  });

  test('empty input works', function () {
    assert.equal(ejs.render(''), '');
  });

  test('undefined renders nothing escaped', function () {
    assert.equal(ejs.render('<%= undefined %>'), '');
  });

  test('undefined renders nothing raw', function () {
    assert.equal(ejs.render('<%- undefined %>'), '');
  });

  test('null renders nothing escaped', function () {
    assert.equal(ejs.render('<%= null %>'), '');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,6 +166,21 @@
     assert.equal(ejs.render(fixture('strict.ejs'), {}, {strict: true}), 'true');
   });
 
+});
+
+/* Old API -- remove when this shim goes away */
+suite('ejs.render(str, dataAndOpts)', function () {
+  test('render the template with data/opts passed together', function () {
+    assert.equal(ejs.render('<p><?= foo ?></p>', {foo: 'yay', delimiter: '?'}),
+        '<p>yay</p>');
+  });
+
+  test('disallow unsafe opts passed along in data', function () {
+    assert.equal(ejs.render('<p><?= locals.foo ?></p>',
+        // localsName should not get reset because it's blacklisted
+        {_with: false, foo: 'yay', delimiter: '?', localsName: '_'}),
+        '<p>yay</p>');
+  });
 });
 
 suite('ejs.render(str, data, opts)', function () {
@@ -753,7 +768,6 @@
     var viewsPath = path.join(__dirname, 'fixtures');
     assert.equal(ejs.render(fixture('include-root.ejs'), {pets: users}, {filename: file, delimiter: '@',root:viewsPath}),
       fixture('include.html'));
-
   });
 
   test('work when nested', function () {
@@ -918,7 +932,7 @@
     var template = fixture('include_preprocessor_line_slurp.ejs');
     var expected = fixture('include_preprocessor_line_slurp.html');
     var options = {rmWhitespace: true, filename: file};
-    assert.equal(ejs.render(template, options),
+    assert.equal(ejs.render(template, {}, options),
         expected);
   });
 
```
