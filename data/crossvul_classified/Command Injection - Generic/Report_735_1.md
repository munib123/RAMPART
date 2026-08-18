# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 735_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `735_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

require 'oj'

module Slanger
  class Connection
    attr_accessor :socket, :socket_id

    def initialize socket, socket_id=nil
      @socket, @socket_id = socket, socket_id
    end

    def send_message m
      msg = Oj.load m
      s = msg.delete 'socket_id'
      socket.send Oj.dump(msg, mode: :compat) unless s == socket_id
    end

    def send_payload *args
      socket.send format(*args)
    end

    def error e
      begin
        send_payload nil, 'pusher:error', e
      rescue EventMachine::WebSocket::WebSocketError
        # Raised if connecection already closed. Only seen with Thor load testing tool
      end
    end

    def establish
      @socket_id = "%d.%d" % [Process.pid, SecureRandom.random_number(10 ** 6)]

      send_payload nil, 'pusher:connection_established', {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
     end
 
     def send_message m
-      msg = Oj.load m
+      msg = Oj.strict_load m
       s = msg.delete 'socket_id'
       socket.send Oj.dump(msg, mode: :compat) unless s == socket_id
     end
```
