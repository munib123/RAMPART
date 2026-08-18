# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in ruby
**Pair ID:** 4294_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4294_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```ruby
Lines 210-250 of the vulnerable file.

        @accept_encoding = HTTPUtils.parse_qvalues(self['accept-encoding'])
        @accept_language = HTTPUtils.parse_qvalues(self['accept-language'])
      end
      return if @request_method == "CONNECT"
      return if @unparsed_uri == "*"

      begin
        setup_forwarded_info
        @request_uri = parse_uri(@unparsed_uri)
        @path = HTTPUtils::unescape(@request_uri.path)
        @path = HTTPUtils::normalize_path(@path)
        @host = @request_uri.host
        @port = @request_uri.port
        @query_string = @request_uri.query
        @script_name = ""
        @path_info = @path.dup
      rescue
        raise HTTPStatus::BadRequest, "bad URI `#{@unparsed_uri}'."
      end

      if /close/io =~ self["connection"]
        @keep_alive = false
      elsif /keep-alive/io =~ self["connection"]
        @keep_alive = true
      elsif @http_version < "1.1"
        @keep_alive = false
      else
        @keep_alive = true
      end
    end

    ##
    # Generate HTTP/1.1 100 continue response if the client expects it,
    # otherwise does nothing.

    def continue # :nodoc:
      if self['expect'] == '100-continue' && @config[:HTTPVersion] >= "1.1"
        @socket << "HTTP/#{@config[:HTTPVersion]} 100 continue#{CRLF}#{CRLF}"
        @header.delete('expect')
      end
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -227,9 +227,9 @@
         raise HTTPStatus::BadRequest, "bad URI `#{@unparsed_uri}'."
       end
 
-      if /close/io =~ self["connection"]
+      if /\Aclose\z/io =~ self["connection"]
         @keep_alive = false
-      elsif /keep-alive/io =~ self["connection"]
+      elsif /\Akeep-alive\z/io =~ self["connection"]
         @keep_alive = true
       elsif @http_version < "1.1"
         @keep_alive = false
@@ -508,7 +508,7 @@
       return unless socket
       if tc = self['transfer-encoding']
         case tc
-        when /chunked/io then read_chunked(socket, block)
+        when /\Achunked\z/io then read_chunked(socket, block)
         else raise HTTPStatus::NotImplemented, "Transfer-Encoding: #{tc}."
         end
       elsif self['content-length'] || @remaining_size
```
