# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4607_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4607_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 24-64 of the vulnerable file.

    index: '2d'
  }
})

const Entity = mongoose.model('Entity', entitySchema)
const Test = mongoose.model('Test', testSchema)

const route = (...args) => {
  const app = express()
  app.get('/tests', querymen.middleware(...args), (req, res) => {
    Test.find(req.querymen.query, req.querymen.select, req.querymen.cursor).then((items) => {
      res.status(200).json(items)
    }).catch((err) => {
      res.status(500).send(err)
    })
  })

  app.use(querymen.errorHandler())
  return app
}

test('Querymen handler', (t) => {
  t.notOk(querymen.parser('testParser'), 'should not get nonexistent parser')
  t.notOk(querymen.formatter('testFormatter'), 'should not get nonexistent formatter')
  t.notOk(querymen.validator('testValidator'), 'should not get nonexistent validator')

  querymen.parser('testParser', () => 'test')
  querymen.formatter('testFormatter', () => 'test')
  querymen.validator('testValidator', () => ({valid: false}))

  t.ok(querymen.parser('testParser'), 'should get parser')
  t.ok(querymen.formatter('testFormatter'), 'should get formatter')
  t.ok(querymen.validator('testValidator'), 'should get validator')

  let schema = new querymen.Schema({test: String})

  t.ok(schema.parser('testParser'), 'should get parser in schema')
  t.ok(schema.formatter('testFormatter'), 'should get formatter in schema')
  t.ok(schema.validator('testValidator'), 'should get validator in schema')

  t.ok(schema.param('test').parser('testParser'), 'should get parser in param')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,21 @@
   app.use(querymen.errorHandler())
   return app
 }
+
+test('Prototype pollution', (t) => {
+  const { toString } = {}
+
+  querymen.handler('__proto__', 'toString', 'JHU')
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  querymen.handler('formatters', '__proto__', { toString: 'JHU' })
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  querymen.handler('validators', '__proto__', { toString: 'JHU' })
+  t.ok({}.toString === toString, 'should not be vulnerable to prototype pollution')
+
+  t.end()
+})
 
 test('Querymen handler', (t) => {
   t.notOk(querymen.parser('testParser'), 'should not get nonexistent parser')
```
