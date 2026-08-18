# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in ruby
**Pair ID:** 1867_1
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1867_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```ruby
Lines 909-949 of the vulnerable file.

            @socket.write_message msgstr
          else
            @socket.write_message_by_block(&block)
          end
        ensure
          @socket.io.flush
          @socket.io.sync = socket_sync_bak
        end
        recv_response()
      }
      check_response res
      res
    end

    def quit
      getok('QUIT')
    end

    private

    def getok(reqline)
      res = critical {
        @socket.writeline reqline
        recv_response()
      }
      check_response res
      res
    end

    def get_response(reqline)
      @socket.writeline reqline
      recv_response()
    end

    def recv_response
      buf = ''
      while true
        line = @socket.readline
        buf << line << "\n"
        break unless line[3,1] == '-'   # "210-PIPELINING"
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -926,7 +926,15 @@
 
     private
 
+    def validate_line(line)
+      # A bare CR or LF is not allowed in RFC5321.
+      if /[\r\n]/ =~ line
+        raise ArgumentError, "A line must not contain CR or LF"
+      end
+    end
+
     def getok(reqline)
+      validate_line reqline
       res = critical {
         @socket.writeline reqline
         recv_response()
@@ -936,6 +944,7 @@
     end
 
     def get_response(reqline)
+      validate_line reqline
       @socket.writeline reqline
       recv_response()
     end
```
