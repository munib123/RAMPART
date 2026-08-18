# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4607_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4607_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 12-52 of the vulnerable file.

  t.equal(add(null, '123'), '123', 'should add a param with default option string')
  t.equal(add(null, 123), 123, 'should add a param with default option number')
  t.equal(add(null, true), true, 'should add a param with default option boolean')
  t.same(add(null, new Date('2016')), new Date('2016'), 'should add a param with default option date')
  t.same(add(null, /123/i), /123/i, 'should add a param with default option regexp')
  t.equal(add(123, String), '123', 'should add a param with type option string')
  t.equal(add('123', Number), 123, 'should add a param with type option number')
  t.equal(add('123', Boolean), true, 'should add a param with type option boolean')
  t.same(add('2016', Date), new Date('2016'), 'should add a param with type option date')
  t.same(add('123', RegExp), /123/i, 'should add a param with type option regexp')

  t.same(add(null, ['123']), '123', 'should add a param with default option string array')
  t.same(add(null, [123]), 123, 'should add a param with default option number array')
  t.same(add(null, [true]), true, 'should add a param with default option boolean array')
  t.same(add(null, [new Date('2016')]), new Date('2016'), 'should add a param with default option date array')
  t.same(add(null, [/123/i]), /123/i, 'should add a param with default option regexp array')
  t.same(add(123, [String]), '123', 'should add a param with type option string array')
  t.same(add('123,456', [Number]), [123, 456], 'should add a param with type option number array')
  t.same(add('123,0', [Boolean]), [true, false], 'should add a param with type option boolean array')
  t.same(add('2016,2017', [Date]), [new Date('2016'), new Date('2017')], 'should add a param with type option date array')
  t.same(add('123,456', [RegExp]), [/123/i, /123/i], 'should add a param with type option regexp array')
  t.end()
})

test('QuerymenSchema get', (t) => {
  let mySchema = schema()
  mySchema.add('test')
  t.false(schema().get('test'), 'should not get a nonexistent param')
  t.true(mySchema.get('test'), 'should get a param')
  t.end()
})

test('QuerymenSchema set', (t) => {
  let mySchema = schema()
  mySchema.add('test')
  t.false(schema().set('test', '123'), 'should not set a nonexistent param')
  t.true(mySchema.set('test', '123'), 'should set a param')
  t.true(mySchema.set('test', '123', {test: true}).option('test'), 'should set param option')
  t.end()
})

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
   t.same(add('123,456', [Number]), [123, 456], 'should add a param with type option number array')
   t.same(add('123,0', [Boolean]), [true, false], 'should add a param with type option boolean array')
   t.same(add('2016,2017', [Date]), [new Date('2016'), new Date('2017')], 'should add a param with type option date array')
-  t.same(add('123,456', [RegExp]), [/123/i, /123/i], 'should add a param with type option regexp array')
+  t.same(add('123,456', [RegExp]), [/123/i, /456/i], 'should add a param with type option regexp array')
   t.end()
 })
 
```
