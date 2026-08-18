# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 779_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `779_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 99-118 of the vulnerable file.


  // parse subdocuments as Object
  request(route(new Schema({sub: {name: String}})))
    .post('/tests')
    .send({sub: {name: 'test'}})
    .expect(200)
    .end((err, res) => {
      if (err) throw err
      t.same(res.body, {sub: {name: 'test'}}, 'should respond with correct object')
    })

  request(route(new Schema({links: [{icon: String}]})))
    .post('/tests')
    .send({links: [{icon: 'path to icon'}]})
    .expect(200)
    .end((err, res) => {
      if (err) throw err
      t.same(res.body, {links: [{icon: 'path to icon'}]}, 'should respond with correct object')
    })
})
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,3 +116,18 @@
       t.same(res.body, {links: [{icon: 'path to icon'}]}, 'should respond with correct object')
     })
 })
+
+test('Prototype pollution', (t) => {
+  const { toString } = {}
+
+  bodymen.handler('__proto__', 'toString', 'JHU')
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  bodymen.handler('formatters', '__proto__', { toString: 'JHU' })
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  bodymen.handler('validators', '__proto__', { toString: 'JHU' })
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  t.end()
+})
```
