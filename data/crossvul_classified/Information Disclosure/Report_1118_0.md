# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 1118_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1118_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-31 of the vulnerable file.

# frozen_string_literal: true

# AUTHOR: blink <blinketje@gmail.com>; blink#ruby-lang@irc.freenode.net
# bugrep: Andreas Zehnder

require 'rack'
require 'time'
require 'rack/request'
require 'rack/response'
require 'securerandom'

module Rack

  module Session

    module Abstract
      # SessionHash is responsible to lazily load the session from store.

      class SessionHash
        using Module.new {
          refine Hash do
            def transform_keys(&block)
              hash = {}
              each do |key, value|
                hash[block.call(key)] = value
              end
              hash
            end
          end
        } unless {}.respond_to?(:transform_keys)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,10 +8,37 @@
 require 'rack/request'
 require 'rack/response'
 require 'securerandom'
+require 'digest/sha2'
 
 module Rack
 
   module Session
+
+    class SessionId
+      ID_VERSION = 2
+
+      attr_reader :public_id
+
+      def initialize(public_id)
+        @public_id = public_id
+      end
+
+      def private_id
+        "#{ID_VERSION}::#{hash_sid(public_id)}"
+      end
+
+      alias :cookie_value :public_id
+
+      def empty?; false; end
+      def to_s; raise; end
+      def inspect; public_id.inspect; end
+
+      private
+
+      def hash_sid(sid)
+        Digest::SHA256.hexdigest(sid)
+      end
+    end
 
     module Abstract
       # SessionHash is responsible to lazily load the session from store.
@@ -375,13 +402,17 @@
             req.get_header(RACK_ERRORS).puts("Deferring cookie for #{session_id}") if $VERBOSE
           else
             cookie = Hash.new
-            cookie[:value] = data
+            cookie[:value] = cookie_value(data)
             cookie[:expires] = Time.now + options[:expire_after] if options[:expire_after]
             cookie[:expires] = Time.now + options[:max_age] if options[:max_age]
             set_cookie(req, res, cookie.merge!(options))
           end
         end
         public :commit_session
+
+        def cookie_value(data)
+          data
+        end
 
         # Sets the cookie back to the client with session id. We skip the cookie
         # setting if the value didn't change (sid is the same) or expires was given.
@@ -421,6 +452,40 @@
 
         def delete_session(req, sid, options)
           raise '#delete_session not implemented'
+        end
+      end
+
+      class PersistedSecure < Persisted
+        class SecureSessionHash < SessionHash
+          def [](key)
+            if key == "session_id"
+              load_for_read!
+              id.public_id
+            else
+              super
+            end
+          end
+        end
+
+        def generate_sid(*)
+          public_id = super
+
+          SessionId.new(public_id)
+        end
+
+        def extract_session_id(*)
+          public_id = super
+          public_id && SessionId.new(public_id)
+        end
+
+        private
+
+        def session_class
+          SecureSessionHash
+        end
+
+        def cookie_value(data)
+          data.cookie_value
         end
       end
 
```
