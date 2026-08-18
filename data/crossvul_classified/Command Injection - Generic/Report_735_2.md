# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 735_2
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `735_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 8-48 of the vulnerable file.

require 'rack'
require 'oj'

module Slanger
  class Handler

    attr_accessor :connection
    delegate :error, :send_payload, to: :connection

    def initialize(socket, handshake)
      @socket        = socket
      @handshake     = handshake
      @connection    = Connection.new(@socket)
      @subscriptions = {}
      authenticate
    end

    # Dispatches message handling to method with same name as
    # the event name
    def onmessage(msg)
      msg = Oj.load(msg)

      msg['data'] = Oj.load(msg['data']) if msg['data'].is_a? String

      event = msg['event'].gsub(/\Apusher:/, 'pusher_')

      if event =~ /\Aclient-/
        msg['socket_id'] = connection.socket_id
        Channel.send_client_message msg
      elsif respond_to? event, true
        send event, msg
      end

    rescue JSON::ParserError
      error({ code: 5001, message: "Invalid JSON" })
    rescue Exception => e
      error({ code: 500, message: "#{e.message}\n #{e.backtrace.join "\n"}" })
    end

    def onclose

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,9 +25,9 @@
     # Dispatches message handling to method with same name as
     # the event name
     def onmessage(msg)
-      msg = Oj.load(msg)
+      msg = Oj.strict_load(msg)
 
-      msg['data'] = Oj.load(msg['data']) if msg['data'].is_a? String
+      msg['data'] = Oj.strict_load(msg['data']) if msg['data'].is_a? String
 
       event = msg['event'].gsub(/\Apusher:/, 'pusher_')
 
```
