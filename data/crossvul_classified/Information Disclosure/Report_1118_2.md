# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 1118_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1118_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 9-49 of the vulnerable file.

require 'thread'

module Rack
  module Session
    # Rack::Session::Pool provides simple cookie based session management.
    # Session data is stored in a hash held by @pool.
    # In the context of a multithreaded environment, sessions being
    # committed to the pool is done in a merging manner.
    #
    # The :drop option is available in rack.session.options if you wish to
    # explicitly remove the session from the session cache.
    #
    # Example:
    #   myapp = MyRackApp.new
    #   sessioned = Rack::Session::Pool.new(myapp,
    #     :domain => 'foo.com',
    #     :expire_after => 2592000
    #   )
    #   Rack::Handler::WEBrick.run sessioned

    class Pool < Abstract::Persisted
      attr_reader :mutex, :pool
      DEFAULT_OPTIONS = Abstract::ID::DEFAULT_OPTIONS.merge drop: false

      def initialize(app, options = {})
        super
        @pool = Hash.new
        @mutex = Mutex.new
      end

      def generate_sid
        loop do
          sid = super
          break sid unless @pool.key? sid
        end
      end

      def find_session(req, sid)
        with_lock(req) do
          unless sid and session = @pool[sid]
            sid, session = generate_sid, {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
     #   )
     #   Rack::Handler::WEBrick.run sessioned
 
-    class Pool < Abstract::Persisted
+    class Pool < Abstract::PersistedSecure
       attr_reader :mutex, :pool
       DEFAULT_OPTIONS = Abstract::ID::DEFAULT_OPTIONS.merge drop: false
 
@@ -39,15 +39,15 @@
       def generate_sid
         loop do
           sid = super
-          break sid unless @pool.key? sid
+          break sid unless @pool.key? sid.private_id
         end
       end
 
       def find_session(req, sid)
         with_lock(req) do
-          unless sid and session = @pool[sid]
+          unless sid and session = get_session_with_fallback(sid)
             sid, session = generate_sid, {}
-            @pool.store sid, session
+            @pool.store sid.private_id, session
           end
           [sid, session]
         end
@@ -55,14 +55,15 @@
 
       def write_session(req, session_id, new_session, options)
         with_lock(req) do
-          @pool.store session_id, new_session
+          @pool.store session_id.private_id, new_session
           session_id
         end
       end
 
       def delete_session(req, session_id, options)
         with_lock(req) do
-          @pool.delete(session_id)
+          @pool.delete(session_id.public_id)
+          @pool.delete(session_id.private_id)
           generate_sid unless options[:drop]
         end
       end
@@ -73,6 +74,12 @@
       ensure
         @mutex.unlock if @mutex.locked?
       end
+
+      private
+
+      def get_session_with_fallback(sid)
+        @pool[sid.private_id] || @pool[sid.public_id]
+      end
     end
   end
 end
```
