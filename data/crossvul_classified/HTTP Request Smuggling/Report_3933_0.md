# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in ruby
**Pair ID:** 3933_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3933_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```ruby
Lines 268-309 of the vulnerable file.

    end

    private

    def setup_body
      @body_read_start = Process.clock_gettime(Process::CLOCK_MONOTONIC, :millisecond)

      if @env[HTTP_EXPECT] == CONTINUE
        # TODO allow a hook here to check the headers before
        # going forward
        @io << HTTP_11_100
        @io.flush
      end

      @read_header = false

      body = @parser.body

      te = @env[TRANSFER_ENCODING2]

      if te && CHUNKED.casecmp(te) == 0
        return setup_chunked_body(body)
      end

      @chunked_body = false

      cl = @env[CONTENT_LENGTH]

      unless cl
        @buffer = body.empty? ? nil : body
        @body = EmptyBody
        set_ready
        return true
      end

      remain = cl.to_i - body.bytesize

      if remain <= 0
        @body = StringIO.new(body)
        @buffer = nil
        set_ready
        return true
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -285,8 +285,16 @@
 
       te = @env[TRANSFER_ENCODING2]
 
-      if te && CHUNKED.casecmp(te) == 0
-        return setup_chunked_body(body)
+      if te
+        if te.include?(",")
+          te.split(",").each do |part|
+            if CHUNKED.casecmp(part.strip) == 0
+              return setup_chunked_body(body)
+            end
+          end
+        elsif CHUNKED.casecmp(te) == 0
+          return setup_chunked_body(body)
+        end
       end
 
       @chunked_body = false
```
