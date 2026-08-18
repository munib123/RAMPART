# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 4503_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4503_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

'use strict'
var tape = require('tape')
var pull = require('pull-stream')
var ssbKeys = require('ssb-keys')
var box1 = require('ssb-private1/box1')

var createSSB = require('./create-ssb')
var { originalValue } = require('../util')

module.exports = function (opts) {
  var alice = ssbKeys.generate()
  var bob = ssbKeys.generate()
  var charles = ssbKeys.generate()

  /* NOTE
   * This is an older test which was written when box1 encryption was part
   * of this model.
   * To ensure these tests still run, we've added box1 back in.
   *
   * For parts dependent on this, see lines commented with:
   *   DEPENDENCY - ssb-private1
   */

  var ssb = createSSB('test-ssb', { keys: alice })
  ssb.addBoxer(box1(alice).boxer)
  ssb.addUnboxer(box1(alice).unboxer)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,11 +3,12 @@
 var pull = require('pull-stream')
 var ssbKeys = require('ssb-keys')
 var box1 = require('ssb-private1/box1')
+const { promisify } = require('util')
 
 var createSSB = require('./create-ssb')
 var { originalValue } = require('../util')
 
-module.exports = function (opts) {
+module.exports = function () {
   var alice = ssbKeys.generate()
   var bob = ssbKeys.generate()
   var charles = ssbKeys.generate()
@@ -34,13 +35,12 @@
   tape('error when trying to encrypt without boxer', (t) => {
     t.plan(2);
     const darlene = ssbKeys.generate()
-    const darleneSSB = createSSB('test-ssb-darlene', { keys: darlene })
     const darleneFeed = ssb.createFeed(darlene)
     darleneFeed.add(
       { type: "error", recps: [alice, darlene] },
       (err, msg) => {
-	t.ok(err);
-	t.notOk(msg);
+        t.ok(err);
+        t.notOk(msg);
         t.end()
       })
   })
@@ -52,7 +52,7 @@
     var postObserved
     var listener = ssb.post(msg => { postObserved = msg })
 
-    feed.add(boxed, function (err, msg) {
+    feed.add(boxed, function (err) {
       if (err) throw err
       t.notOk(err)
 
@@ -145,7 +145,7 @@
     var listener = ssb.post(msg => { postObserved = msg })
 
     // secret message sent to self
-    feed.add({ type: 'secret2', secret: "it's a secret!", recps: feed.id }, function (err, msg) {
+    feed.add({ type: 'secret2', secret: "it's a secret!", recps: feed.id }, function (err) {
       if (err) throw err
       t.notOk(err)
 
@@ -165,7 +165,7 @@
           )
 
           listener()
-          t.true(typeof postObserved.value.content === 'string', 'post obs messages should not be decrypted')
+          t.true(typeof postObserved.value.content === 'string', 'db.post obs messages should not be decrypted')
 
           t.end()
         })
@@ -264,7 +264,7 @@
   })
 
   tape('addUnboxer (simple)', function (t) {
-    const unboxer = function (ciphertext, value) {
+    const unboxer = function (ciphertext) {
       if (!ciphertext.endsWith('.box.hah')) return
 
       const base64 = ciphertext.replace('.box.hah', '')
@@ -301,12 +301,12 @@
           done()
         }, 500)
       },
-      key: function (ciphertext, value) {
+      key: function (ciphertext) {
         if (!ciphertext.endsWith('.box.hah')) return
 
         return '"the msgKey"'
       },
-      value: function (ciphertext, msgKey) {
+      value: function (ciphertext) {
         const base64 = ciphertext.replace('.box.hah', '')
         return JSON.parse(
           Buffer.from(base64, 'base64').toString('utf8')
@@ -319,19 +319,87 @@
     const content = {
       type: 'poke',
       reason: 'why not',
-      recps: [ '!test' ]
+      recps: [ '!test' ],
+      myFriend: alice.id// Necessary to test links()
     }
     const ciphertext = Buffer.from(JSON.stringify(content)).toString('base64') + '.box.hah'
 
     feed.publish(ciphertext, (_, msg) => {
       t.true(initDone, 'unboxer completed initialisation before publish')
 
-      ssb.get({ id: msg.key, private: true, meta: true }, (err, msg) => {
-        if (err) throw err
+      ssb.get({ id: msg.key, private: true, meta: true }, async (err, msg) => {
+        t.error(err)
 
         t.true(initDone, 'unboxer completed initialisation before get')
         t.deepEqual(msg.value.content, content, 'auto unboxing works')
+
+        const assertBoxed = (methodName, message) => {
+          if (typeof message.key === 'string') {
+            t.equal(message.key, msg.key, `${methodName}() returned correct message`)
+            t.equal(typeof message.value.content, 'string', `${methodName}() does not unbox by default`)
+          } else {
+            t.equal(typeof message.content, 'string', `${methodName}() does not unbox by default`)
+          }
+        }
+
+        const assertBoxedAsync = async (methodName, options) => {
+          assertBoxed(methodName, await promisify(ssb[methodName])(options))
+          if (typeof options === 'object' && Array.isArray(options) === false) {
+            assertBoxed(methodName, await promisify(ssb[methodName])({ ...options, private: false } ))
+          }
+        }
+
+        // This tests the default behavior of `ssb.get()`, which should never
+        // decrypt messages by default. This is **very important**.
+        await assertBoxedAsync('get', msg.key)
+        await assertBoxedAsync('get', { id: msg.key })
+        await assertBoxedAsync('get', { id: msg.key, meta: true })
+        await assertBoxedAsync('getAtSequence', [msg.value.author, msg.value.sequence])
+        await assertBoxedAsync('getLatest', msg.value.author)
+
+        const assertBoxedSourceOnce = (methodName, options) => new Promise((resolve) => {
+          pull(
+            ssb[methodName](options),
+            pull.collect((err, val) => {
+              t.error(err, `${methodName}() does not error`)
+              switch (methodName) {
+                case 'createRawLogStream':
+                  assertBoxed(methodName, val[0].value)
+                  break;
+                case 'createFeedStream':
+                case 'createUserStream':
+                case 'messagesByType':
+                  // Apparently some methods take `{ private: false }` to mean
+                  // "don't return any private messages". :/
+                  if (options.private === undefined) {
+                    assertBoxed(methodName, val[0].value)
+                  }
+                  break
+                default:
+                  assertBoxed(methodName, val[0])
+              }
+              resolve()
+            })
+          )
+        })
+
+        // Test the default **and** `{ private: false }`.
+        const assertBoxedSource = async (methodName, options) => {
+          await assertBoxedSourceOnce(methodName, options)
+          await assertBoxedSourceOnce(methodName, { ...options, private: false })
+        }
+
+        await assertBoxedSource('createLogStream', { limit: 1, reverse: true })
+        await assertBoxedSource('createHistoryStream', { id: msg.value.author, seq: msg.value.sequence, reverse: true})
+        await assertBoxedSource('messagesByType', { type: 'poke', limit: 1, reverse: true })
+        await assertBoxedSource('createFeedStream', { id: msg.value.author, seq: msg.value.sequence, reverse: true})
+        await assertBoxedSource('createUserStream', { id: msg.value.author, seq: msg.value.sequence, reverse: true})
+        await assertBoxedSource('links', { source: msg.value.author, limit: 1, values: true})
+        await assertBoxedSource('createRawLogStream', { source: msg.value.author, limit: 1, reverse: true, values: true})
+        // createRawLogStream currently not exported as a method
+
         t.end()
+
       })
     })
   })
```
