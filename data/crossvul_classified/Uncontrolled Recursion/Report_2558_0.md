# CrossVul Fix Pair: Uncontrolled Recursion in javascript
**Pair ID:** 2558_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2558_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```javascript
Lines 232-272 of the vulnerable file.

 * setup the event handlers in the inner stream.
 *
 * @api private
 */
MqttClient.prototype._setupStream = function () {
  var connectPacket
  var that = this
  var writable = new Writable()
  var parser = mqttPacket.parser(this.options)
  var completeParse = null
  var packets = []

  this._clearReconnect()

  this.stream = this.streamBuilder(this)

  parser.on('packet', function (packet) {
    packets.push(packet)
  })

  function process () {
    var packet = packets.shift()
    var done = completeParse

    if (packet) {
      that._handlePacket(packet, process)
    } else {
      completeParse = null
      done()
    }
  }

  writable._write = function (buf, enc, done) {
    completeParse = done
    parser.parse(buf)
    process()
  }

  this.stream.pipe(writable)

  // Suppress connection errors
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -249,12 +249,16 @@
     packets.push(packet)
   })
 
-  function process () {
+  function nextTickWork () {
+    process.nextTick(work)
+  }
+
+  function work () {
     var packet = packets.shift()
     var done = completeParse
 
     if (packet) {
-      that._handlePacket(packet, process)
+      that._handlePacket(packet, nextTickWork)
     } else {
       completeParse = null
       done()
@@ -264,7 +268,7 @@
   writable._write = function (buf, enc, done) {
     completeParse = done
     parser.parse(buf)
-    process()
+    work()
   }
 
   this.stream.pipe(writable)
```
