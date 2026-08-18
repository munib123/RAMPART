# CrossVul Fix Pair: Incorrect Regular Expression in javascript
**Pair ID:** 529_2
**Vulnerability Class:** Incorrect Regular Expression
**CWE:** CWE-185
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `529_2`)

## Vulnerability Information & PoC

## Description
Incorrect Regular Expression - When the regular expression is used in protection mechanisms such as filtering or validation, this may allow an attacker to bypass the intended restrictions on the incoming data.

## Vulnerable Code
```javascript
Lines 187-206 of the vulnerable file.

        400
    );

    var label = ren.label('Hello', 100, 100)
        .attr({
            stroke: 'blue',
            'stroke-width': 1,
            padding: 0
        })
        .add();

    assert.close(
        label.text.element.getBBox().x,
        0,
        2,
        'Label sits nicely inside box'
    );

    document.getElementById('container').removeAttribute('dir');
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,3 +204,39 @@
 
     document.getElementById('container').removeAttribute('dir');
 });
+
+QUnit.test('Attributes', function (assert) {
+    var ren = new Highcharts.Renderer(
+        document.getElementById('container'),
+        600,
+        400
+    );
+
+    var text = ren
+        .text(
+            'The quick brown fox jumps <span class="red">over</span> the lazy dog',
+            20,
+            20
+        )
+        .add();
+
+    assert.strictEqual(
+        text.element.childNodes[1].getAttribute('class'),
+        'red',
+        'Double quotes, red span should be picked up'
+    );
+
+    text = ren
+        .text(
+            "The quick brown fox jumps <span class='red'>over</span> the lazy dog",
+            20,
+            20
+        )
+        .add();
+
+    assert.strictEqual(
+        text.element.childNodes[1].getAttribute('class'),
+        'red',
+        'Single quotes, red span should be picked up'
+    );
+});
```
