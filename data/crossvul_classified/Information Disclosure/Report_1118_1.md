# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 1118_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1118_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 31-71 of the vulnerable file.

    #                                :old_secret => 'also_change_me'
    #
    #     All parameters are optional.
    #
    # Example of a cookie with no encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Rack::Session::Cookie::Identity.new
    #   })
    #
    # Example of a cookie with custom encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Class.new {
    #       def encode(str); str.reverse; end
    #       def decode(str); str.reverse; end
    #     }.new
    #   })
    #

    class Cookie < Abstract::Persisted
      # Encode session cookies as Base64
      class Base64
        def encode(str)
          ::Base64.encode64(str)
        end

        def decode(str)
          ::Base64.decode64(str)
        end

        # Encode session cookies as Marshaled Base64 data
        class Marshal < Base64
          def encode(str)
            super(::Marshal.dump(str))
          end

          def decode(str)
            return unless str
            ::Marshal.load(super(str)) rescue nil
          end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
     #   })
     #
 
-    class Cookie < Abstract::Persisted
+    class Cookie < Abstract::PersistedSecure
       # Encode session cookies as Base64
       class Base64
         def encode(str)
@@ -154,6 +154,15 @@
         data
       end
 
+      class SessionId < DelegateClass(Session::SessionId)
+        attr_reader :cookie_value
+
+        def initialize(session_id, cookie_value)
+          super(session_id)
+          @cookie_value = cookie_value
+        end
+      end
+
       def write_session(req, session_id, session, options)
         session = session.merge("session_id" => session_id)
         session_data = coder.encode(session)
@@ -166,7 +175,7 @@
           req.get_header(RACK_ERRORS).puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
           nil
         else
-          session_data
+          SessionId.new(session_id, session_data)
         end
       end
 
```
