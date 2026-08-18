# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4551_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4551_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 646-686 of the vulnerable file.

      end

      env[HIJACK_P] = true
      env[HIJACK] = req

      body = req.body

      head = env[REQUEST_METHOD] == HEAD

      env[RACK_INPUT] = body
      env[RACK_URL_SCHEME] = default_server_port(env) == PORT_443 ? HTTPS : HTTP

      if @early_hints
        env[EARLY_HINTS] = lambda { |headers|
          begin
            fast_write client, "HTTP/1.1 103 Early Hints\r\n".freeze

            headers.each_pair do |k, vs|
              if vs.respond_to?(:to_s) && !vs.to_s.empty?
                vs.to_s.split(NEWLINE).each do |v|
                  fast_write client, "#{k}: #{v}\r\n"
                end
              else
                fast_write client, "#{k}: #{vs}\r\n"
              end
            end

            fast_write client, "\r\n".freeze
          rescue ConnectionError
            # noop, if we lost the socket we just won't send the early hints
          end
        }
      end

      # A rack extension. If the app writes #call'ables to this
      # array, we will invoke them when the request is done.
      #
      after_reply = env[RACK_AFTER_REPLY] = []

      begin
        begin
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -663,6 +663,7 @@
             headers.each_pair do |k, vs|
               if vs.respond_to?(:to_s) && !vs.to_s.empty?
                 vs.to_s.split(NEWLINE).each do |v|
+                  next if possible_header_injection?(v)
                   fast_write client, "#{k}: #{v}\r\n"
                 end
               else
@@ -687,8 +688,6 @@
           status, headers, res_body = @app.call(env)
 
           return :async if req.hijacked
-          # Checking to see if an attacker is trying to inject headers into the response
-          headers.reject! { |_k, v| CRLF_REGEX =~ v.to_s }
 
           status = status.to_i
 
@@ -766,6 +765,7 @@
         headers.each do |k, vs|
           case k.downcase
           when CONTENT_LENGTH2
+            next if possible_header_injection?(vs)
             content_length = vs
             next
           when TRANSFER_ENCODING
@@ -778,6 +778,7 @@
 
           if vs.respond_to?(:to_s) && !vs.to_s.empty?
             vs.to_s.split(NEWLINE).each do |v|
+              next if possible_header_injection?(v)
               lines.append k, colon, v, line_ending
             end
           else
@@ -1048,5 +1049,10 @@
     def shutting_down?
       @status == :stop || @status == :restart
     end
+
+    def possible_header_injection?(header_value)
+      HTTP_INJECTION_REGEX =~ header_value.to_s
+    end
+    private :possible_header_injection?
   end
 end
```
