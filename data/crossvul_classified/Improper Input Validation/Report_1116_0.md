# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1116_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1116_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 245-285 of the vulnerable file.

      end

      if datum[:scheme] == UNIX
        datum[:headers]['Host']   ||= ''
      else
        datum[:headers]['Host']   ||= datum[:host] + port_string(datum)
      end

      # if path is empty or doesn't start with '/', insert one
      unless datum[:path][0, 1] == '/'
        datum[:path] = datum[:path].dup.insert(0, '/')
      end

      if block_given?
        Excon.display_warning('Excon requests with a block are deprecated, pass :response_block instead.')
        datum[:response_block] = block
      end

      datum[:connection] = self

      datum[:stack] = datum[:middlewares].map do |middleware|
        lambda {|stack| middleware.new(stack)}
      end.reverse.inject(self) do |middlewares, middleware|
        middleware.call(middlewares)
      end
      datum = datum[:stack].request_call(datum)

      unless datum[:pipeline]
        datum = response(datum)

        if datum[:persistent]
          if key = datum[:response][:headers].keys.detect {|k| k.casecmp('Connection') == 0 }
            if datum[:response][:headers][key].casecmp('close') == 0
              reset
            end
          end
        else
          reset
        end

        Excon::Response.new(datum[:response])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,6 +262,11 @@
 
       datum[:connection] = self
 
+      # cleanup data left behind on persistent connection after interrupt
+      if datum[:persistent] && !@persistent_socket_reusable
+        reset
+      end
+
       datum[:stack] = datum[:middlewares].map do |middleware|
         lambda {|stack| middleware.new(stack)}
       end.reverse.inject(self) do |middlewares, middleware|
@@ -270,7 +275,9 @@
       datum = datum[:stack].request_call(datum)
 
       unless datum[:pipeline]
+        @persistent_socket_reusable = false
         datum = response(datum)
+        @persistent_socket_reusable = true
 
         if datum[:persistent]
           if key = datum[:response][:headers].keys.detect {|k| k.casecmp('Connection') == 0 }
@@ -344,6 +351,7 @@
       if old_socket = sockets.delete(@socket_key)
         old_socket.close rescue nil
       end
+      @persistent_socket_reusable = true
     end
 
     # Generate HTTP request verb methods
```
