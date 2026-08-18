# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4644_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4644_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 34-73 of the vulnerable file.

    let doc = {};
    const patch = { foo: "bar", bar: "foo" };
    doc = apply(doc, patch);
    assert.deepEqual(doc, patch);
  });

  it("adds nested patch properties with non null value", () => {
    let doc = {};
    const patch = { foo: { bar: "foo" } };
    doc = apply(doc, patch);
    assert.deepEqual(doc, patch);
  });

  it("ignores inherited properties on patch", () => {
    let doc = {};
    const patch = Object.create({ foo: "bar" });
    doc = apply(doc, patch);
    assert.deepEqual(doc, {});
  });

  // https://github.com/lodash/lodash/pull/4337
  it("prevents prototype pollution", () => {
    let doc = {};
    const patch = { __proto__: { foobar: true } };
    doc = apply(doc, patch);

    assert.deepEqual(doc, {});
  });

  // https://github.com/lodash/lodash/pull/4336
  it("prevents constructor pollution", () => {
    let doc = {};

    const patch = { constructor: { foo: "bar" } };
    doc = apply(doc, patch);
    assert.equal("foo" in Object, false);
    assert.equal(Object.foo, undefined);
    assert.deepEqual(doc, patch);
  });
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,23 +51,21 @@
     assert.deepEqual(doc, {});
   });
 
-  // https://github.com/lodash/lodash/pull/4337
+  // https://github.com/sonnyp/JSON8/issues/113
+  // https://github.com/HoLyVieR/prototype-pollution-nsec18
   it("prevents prototype pollution", () => {
     let doc = {};
-    const patch = { __proto__: { foobar: true } };
-    doc = apply(doc, patch);
+    const patch = JSON.parse('{ "__proto__": { "isAdmin": true }}');
 
-    assert.deepEqual(doc, {});
-  });
+    assert.throws(
+      () => {
+        doc = apply(doc, patch);
+      },
+      Error,
+      "Prototype pollution attempt"
+    );
 
-  // https://github.com/lodash/lodash/pull/4336
-  it("prevents constructor pollution", () => {
-    let doc = {};
-
-    const patch = { constructor: { foo: "bar" } };
-    doc = apply(doc, patch);
-    assert.equal("foo" in Object, false);
-    assert.equal(Object.foo, undefined);
-    assert.deepEqual(doc, patch);
+    assert.equal(doc.isAdmin, undefined);
+    assert.equal("isAdmin" in doc, false);
   });
 });
```
