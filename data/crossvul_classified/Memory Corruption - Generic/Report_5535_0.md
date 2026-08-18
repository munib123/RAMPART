# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in ruby
**Pair ID:** 5535_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5535_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```ruby
Lines 53-95 of the vulnerable file.


        @boundary_size = Utils.bytesize(@boundary) + EOL.size

        if @content_length = @env['CONTENT_LENGTH']
          @content_length = @content_length.to_i
          @content_length -= @boundary_size
        end
        true
      end

      def full_boundary
        @boundary + EOL
      end

      def rx
        @rx ||= /(?:#{EOL})?#{Regexp.quote(@boundary)}(#{EOL}|--)/n
      end

      def fast_forward_to_first_boundary
        loop do
          read_buffer = @io.gets
          break if read_buffer == full_boundary
          raise EOFError, "bad content body" if read_buffer.nil?
        end
      end

      def get_current_head_and_filename_and_content_type_and_name_and_body
        head = nil
        body = ''
        filename = content_type = name = nil
        content = nil

        until head && @buf =~ rx
          if !head && i = @buf.index(EOL+EOL)
            head = @buf.slice!(0, i+2) # First \r\n

            @buf.slice!(0, 2)          # Second \r\n

            content_type = head[MULTIPART_CONTENT_TYPE, 1]
            name = head[MULTIPART_CONTENT_DISPOSITION, 1] || head[MULTIPART_CONTENT_ID, 1]

            filename = get_filename(head)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,9 +70,16 @@
 
       def fast_forward_to_first_boundary
         loop do
-          read_buffer = @io.gets
-          break if read_buffer == full_boundary
-          raise EOFError, "bad content body" if read_buffer.nil?
+          content = @io.read(BUFSIZE)
+          raise EOFError, "bad content body" unless content
+          @buf << content
+
+          while @buf.gsub!(/\A([^\n]*\n)/, '')
+            read_buffer = $1
+            return if read_buffer == full_boundary
+          end
+
+          raise EOFError, "bad content body" if Utils.bytesize(@buf) >= BUFSIZE
         end
       end
 
```
