# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 5859_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5859_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 38-72 of the vulnerable file.

 *  - time    Set the expiration time
 *  - image
 *    - path to an image sets -i ( you can also use stock icons )
 *
 * Examples:
 *
 *   growl.notify('New email')
 *   growl.notify('5 new emails', { title: 'Thunderbird' })
 *   growl.notify('Email sent', function(){
 *     // ... notification sent
 *   })
 *
 * @param {string} msg
 * @param {object} options
 * @param {function} callback
 * @api public
 */

exports.notify = function(msg, options, callback) {
  var image,
      args = ['notify-send','"' + msg + '"'],
      options = options || {}
  this.binVersion(function(err, version){
    if (err) return callback(err)
    if (image = options.image) args.push('-i ' + image)
    if (options.time) args.push('-t', options.time)
    if (options.category) args.push('-c', options.category)
    if (options.urgency) args.push('-u', options.urgency)
    if (options.title) {
      args.shift()
      args.unshift('notify-send', '"'+ options.title +'"')
    }
    child_process.exec(args.join(' '), callback)
  })
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,18 +55,17 @@
 
 exports.notify = function(msg, options, callback) {
   var image,
-      args = ['notify-send','"' + msg + '"'],
+      args = [msg],
       options = options || {}
   this.binVersion(function(err, version){
     if (err) return callback(err)
-    if (image = options.image) args.push('-i ' + image)
+    if (image = options.image) args.push('-i', image)
     if (options.time) args.push('-t', options.time)
     if (options.category) args.push('-c', options.category)
     if (options.urgency) args.push('-u', options.urgency)
     if (options.title) {
-      args.shift()
-      args.unshift('notify-send', '"'+ options.title +'"')
+      args.unshift(options.title)
     }
-    child_process.exec(args.join(' '), callback)
+    child_process.execFile('notify-send', args, {}, callback)
   })
 }
```
