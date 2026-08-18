# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 5522_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5522_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 163-203 of the vulnerable file.

    # Return +true+ if this connection is allowed to stay open and be persistent.
    def can_persist?
      @can_persist
    end

    # Return +true+ if the connection must be left open
    # and ready to be reused for another request.
    def persistent?
      @can_persist && @response.persistent?
    end

    # +true+ if <tt>app.call</tt> will be called inside a thread.
    # You can set all requests as threaded setting <tt>Connection#threaded=true</tt>
    # or on a per-request case returning +true+ in <tt>app.deferred?</tt>.
    def threaded?
      @threaded || (@app.respond_to?(:deferred?) && @app.deferred?(@request.env))
    end

    # IP Address of the remote client.
    def remote_address
      @request.forwarded_for || socket_address
    rescue Exception
      log_error
      nil
    end

    protected

      # Returns IP address of peer as a string.
      def socket_address
        Socket.unpack_sockaddr_in(get_peername)[1]
      end

    private
      def need_content_length?(result)
        status, headers, body = result
        return false if status == -1
        return false if headers.has_key?(CONTENT_LENGTH)
        return false if (100..199).include?(status) || status == 204 || status == 304
        return false if headers.has_key?(TRANSFER_ENCODING) && headers[TRANSFER_ENCODING] =~ CHUNKED_REGEXP
        return false unless body.kind_of?(String) || body.kind_of?(Array)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,7 +180,7 @@
 
     # IP Address of the remote client.
     def remote_address
-      @request.forwarded_for || socket_address
+      socket_address
     rescue Exception
       log_error
       nil
```
