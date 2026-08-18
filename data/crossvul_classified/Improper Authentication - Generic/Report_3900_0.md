# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 3900_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3900_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

module Faye
  class Server

    autoload :Socket, File.join(ROOT, 'faye', 'protocol', 'socket')

    include Logging
    include Extensible

    META_METHODS = %w[handshake connect disconnect subscribe unsubscribe]

    attr_reader :engine

    def initialize(options = {})
      @options    = options || {}
      engine_opts = @options[:engine] || {}
      engine_opts[:timeout] = @options[:timeout]
      @engine     = Faye::Engine.get(engine_opts)

      info('Created new server: ?', @options)
    end

    def close
      @engine.close
    end

    def open_socket(client_id, socket, env)
      return unless client_id and socket
      @engine.open_socket(client_id, Socket.new(self, socket, env))
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,8 +5,6 @@
 
     include Logging
     include Extensible
-
-    META_METHODS = %w[handshake connect disconnect subscribe unsubscribe]
 
     attr_reader :engine
 
@@ -107,9 +105,9 @@
     end
 
     def handle_meta(message, local, &callback)
-      method = Channel.parse(message['channel'])[1]
-
-      unless META_METHODS.include?(method)
+      method = method_for(message)
+
+      unless method
         response = make_response(message)
         response['error'] = Faye::Error.channel_forbidden(message['channel'])
         response['successful'] = false
@@ -120,6 +118,16 @@
         responses = [responses].flatten
         responses.each { |r| advize(r, message['connectionType']) }
         callback.call(responses)
+      end
+    end
+
+    def method_for(message)
+      case message['channel']
+      when Channel::HANDSHAKE   then :handshake
+      when Channel::CONNECT     then :connect
+      when Channel::SUBSCRIBE   then :subscribe
+      when Channel::UNSUBSCRIBE then :unsubscribe
+      when Channel::DISCONNECT  then :disconnect
       end
     end
 
```
