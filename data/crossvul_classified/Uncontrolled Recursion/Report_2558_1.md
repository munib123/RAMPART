# CrossVul Fix Pair: Uncontrolled Recursion in javascript
**Pair ID:** 2558_1
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2558_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

'use strict'

var mqtt = require('..')
var should = require('should')
var fork = require('child_process').fork
var path = require('path')
var abstractClientTests = require('./abstract_client')
var net = require('net')
var eos = require('end-of-stream')
var Connection = require('mqtt-connection')
var Server = require('./server')
var port = 9876
var server

/**
 * Test server
 */
function buildServer () {
  return new Server(function (client) {
    client.on('connect', function (packet) {
      if (packet.clientId === 'invalid') {
        client.connack({returnCode: 2})
      } else {
        client.connack({returnCode: 0})
      }
    })

    client.on('publish', function (packet) {
      setImmediate(function () {
        switch (packet.qos) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,9 @@
 var abstractClientTests = require('./abstract_client')
 var net = require('net')
 var eos = require('end-of-stream')
+var mqttPacket = require('mqtt-packet')
+var Buffer = require('safe-buffer').Buffer
+var Duplex = require('readable-stream').Duplex
 var Connection = require('mqtt-connection')
 var Server = require('./server')
 var port = 9876
@@ -146,6 +149,54 @@
             done()
           }
         })
+      })
+    })
+
+    it('should not go overflow if the TCP frame contains a lot of PUBLISH packets', function (done) {
+      var parser = mqttPacket.parser()
+      var count = 0
+      var max = 1000
+      var duplex = new Duplex({
+        read: function (n) {},
+        write: function (chunk, enc, cb) {
+          parser.parse(chunk)
+          cb() // nothing to do
+        }
+      })
+      var client = new mqtt.MqttClient(function () {
+        return duplex
+      }, {})
+
+      client.on('message', function (t, p, packet) {
+        if (++count === max) {
+          done()
+        }
+      })
+
+      parser.on('packet', function (packet) {
+        var packets = []
+
+        if (packet.cmd === 'connect') {
+          duplex.push(mqttPacket.generate({
+            cmd: 'connack',
+            sessionPresent: false,
+            returnCode: 0
+          }))
+
+          for (var i = 0; i < max; i++) {
+            packets.push(mqttPacket.generate({
+              cmd: 'publish',
+              topic: Buffer.from('hello'),
+              payload: Buffer.from('world'),
+              retain: false,
+              dup: false,
+              messageId: i + 1,
+              qos: 1
+            }))
+          }
+
+          duplex.push(Buffer.concat(packets))
+        }
       })
     })
   })
```
