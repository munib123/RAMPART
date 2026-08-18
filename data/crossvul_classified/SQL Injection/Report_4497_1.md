# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4497_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4497_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 420-460 of the vulnerable file.

      const m1 = mockTaskRaw({ id: 't1', text1: 'bar1', order: 1 })
      const m2 = mockTaskRaw({ id: 't2', text1: 'bar2', order: 2 })
      const m3 = mockTaskRaw({ id: 't3', text1: 'bar3', order: 3 })
      await adapter.batch([
        ['create', 'tasks', m1],
        ['create', 'tasks', m2],
        ['create', 'tasks', m3],
        ['create', 'tasks', mockTaskRaw({ id: 't4', text1: 'bar4' })],
      ])
      await adapter.batch([
        ['markAsDeleted', 'tasks', m1.id],
        ['markAsDeleted', 'tasks', m2.id],
        ['markAsDeleted', 'tasks', m3.id],
      ])

      await adapter.destroyDeletedRecords('tasks', ['t1', 't2'])
      expectSortedEqual(await adapter.getDeletedRecords('tasks'), ['t3'])
      expectSortedEqual(await adapter.query(taskQuery()), ['t4'])
      expect(await adapter.find('tasks', 't1')).toBeNull()
      expect(await adapter.find('tasks', 't2')).toBeNull()
    },
  ],
  [
    'can run mixed batches',
    async _adapter => {
      let adapter = _adapter
      const m1 = mockTaskRaw({ id: 't1', text1: 'bar' })
      const m3 = mockTaskRaw({ id: 't3' })
      const m4 = mockTaskRaw({ id: 't4' })

      await adapter.batch([['create', 'tasks', m1]])

      m1.bool1 = true
      const m2 = mockTaskRaw({ id: 't2', text1: 'bar', bool2: true, order: 2 })

      await adapter.batch([
        ['create', 'tasks', m3],
        ['create', 'tasks', m4],
        ['destroyPermanently', 'tasks', m3.id],
        ['update', 'tasks', m1],
        ['create', 'tasks', m2],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -437,6 +437,31 @@
       expectSortedEqual(await adapter.query(taskQuery()), ['t4'])
       expect(await adapter.find('tasks', 't1')).toBeNull()
       expect(await adapter.find('tasks', 't2')).toBeNull()
+    },
+  ],
+  [
+    'destroyDeletedRecords can handle unsafe strings',
+    async adapter => {
+      const m1 = mockTaskRaw({ id: 't1', text1: 'bar1', order: 1 })
+      const m2 = mockTaskRaw({ id: 't2', text1: 'bar2', order: 2 })
+      const m3 = mockTaskRaw({ id: 't3', text1: 'bar3', order: 3 })
+      await adapter.batch([
+        ['create', 'tasks', m1],
+        ['create', 'tasks', m2],
+        ['create', 'tasks', m3],
+      ])
+      await adapter.batch([
+        ['markAsDeleted', 'tasks', m1.id],
+        ['markAsDeleted', 'tasks', m2.id],
+        ['markAsDeleted', 'tasks', m3.id],
+      ])
+
+      await adapter.destroyDeletedRecords('tasks', ['\') or 1=1 --'])
+      expectSortedEqual(await adapter.getDeletedRecords('tasks'), ['t1', 't2', 't3'])
+      expectSortedEqual(await adapter.query(taskQuery()), [])
+
+      await adapter.destroyDeletedRecords('tasks', ['\'); insert into tasks (id) values (\'t4\') --'])
+      expectSortedEqual(await adapter.query(taskQuery()), [])
     },
   ],
   [
```
