# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in coffeescript
**Pair ID:** 5858_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5858_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```coffeescript
Lines 1-33 of the vulnerable file.

# Description:
#   Email from hubot to any address
#
# Dependencies:
#   None
#
# Configuration:
#   None
#
# Commands:
#   hubot email <user@email.com> -s <subject> -m <message> - Sends email with the <subject> <message> to address <user@email.com>
#
# Author:
#   earlonrails
#
# Additional Requirements
#   unix mail client installed on the system

util = require 'util'
child_process = require 'child_process'
exec = child_process.exec

module.exports = (robot) ->
  emailTime = null
  sendEmail = (recipients, subject, msg, from) ->
    mailCommand = """echo '#{msg}' | mail -s '#{subject}' -r '#{from}' '#{recipients}'"""
    exec mailCommand, (error, stdout, stderr) ->
      util.print 'stdout: ' + stdout
      util.print 'stderr: ' + stderr

  robot.respond /email (.*) -s (.*) -m (.*)/i, (msg) ->
    sendEmail msg.match[1], msg.match[2], msg.match[3], msg.message.user.id
    msg.send "email sent"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,16 +18,18 @@
 
 util = require 'util'
 child_process = require 'child_process'
-exec = child_process.exec
 
 module.exports = (robot) ->
   emailTime = null
   sendEmail = (recipients, subject, msg, from) ->
-    mailCommand = """echo '#{msg}' | mail -s '#{subject}' -r '#{from}' '#{recipients}'"""
-    exec mailCommand, (error, stdout, stderr) ->
+    mailArgs = ['-s', subject, '-a', "From: #{from}", '--']
+    mailArgs = mailArgs.concat recipients
+    p = child_process.execFile 'mail', mailArgs, {}, (error, stdout, stderr) ->
       util.print 'stdout: ' + stdout
       util.print 'stderr: ' + stderr
+    p.stdin.write "#{msg}\n"
+    p.stdin.end()
 
   robot.respond /email (.*) -s (.*) -m (.*)/i, (msg) ->
-    sendEmail msg.match[1], msg.match[2], msg.match[3], msg.message.user.id
+    sendEmail msg.match[1].split(" "), msg.match[2], msg.match[3], msg.message.user.id
     msg.send "email sent"
```
