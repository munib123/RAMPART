# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 4503_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4503_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 67-108 of the vulnerable file.

      cb(new Error('deletion target must be a message or feed'))
    }
  }

  db.get = function (key, cb) {
    let isPrivate = false
    let unbox
    let meta = false
    if (typeof key === 'object') {
      isPrivate = key.private === true
      unbox = key.unbox
      meta = key.meta
      key = key.id
    }

    if (ref.isMsg(key)) {
      return db.keys.get(key, function (err, data) {
        if (err) return cb(err)

        if (!isPrivate) {
          if (meta) cb(null, { key, value: data.value, timestamp: data.timestamp })
          else cb(null, data.value)
        }
        else {
          const result = db._unbox(data, unbox)

          if (meta) cb(null, { key, value: result.value, timestamp: result.timestamp })
          else cb(null, result.value)
        }
      })
    } else if (ref.isMsgLink(key)) {
      var link = ref.parseLink(key)
      return db.get({
        id: link.link,
        private: true,
        unbox: link.query.unbox.replace(/\s/g, '+'),
        meta: link.query.meta
      }, cb)
    } else if (Number.isInteger(key)) {
      _get(key, cb) // seq
    } else {
      throw new Error('ssb-db.get: key *must* be a ssb message id or a flume offset')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,8 +84,8 @@
         if (err) return cb(err)
 
         if (!isPrivate) {
-          if (meta) cb(null, { key, value: data.value, timestamp: data.timestamp })
-          else cb(null, data.value)
+          if (meta) cb(null, { key, value: u.originalValue(data.value), timestamp: data.timestamp })
+          else cb(null, u.originalValue(data.value))
         }
         else {
           const result = db._unbox(data, unbox)
@@ -133,12 +133,25 @@
   }
 
   db.createRawLogStream = function (opts) {
-    return db.stream(opts)
+    return pull(
+      db.stream(opts),
+      pull.map(({ seq, value }) => {
+        return { seq, value: u.originalData(value) }
+      })
+    )
   }
 
   // pull in the features that are needed to pass the tests
   // and that sbot, etc uses but are slow.
   extras(db, opts, keys)
+  // - adds indexes: links, feed, time
+  // - adds methods:
+  //   - db.createLogStream
+  //   - db.createFeedStream
+  //   - db.creareUserStream
+  //   - db.latest
+  //   - db.latestSequence
+  //   - db.getLatest
 
   // writeStream - used in (legacy) replication.
   db.createWriteStream = function (cb) {
```
