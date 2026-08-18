# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 5522_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5522_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 4-44 of the vulnerable file.

module Thin
  # Raised when an incoming request is not valid
  # and the server can not process it.
  class InvalidRequest < IOError; end

  # A request sent by the client to the server.
  class Request
    # Maximum request body size before it is moved out of memory
    # and into a tempfile for reading.
    MAX_BODY          = 1024 * (80 + 32)
    BODY_TMPFILE      = 'thin-body'.freeze
    MAX_HEADER        = 1024 * (80 + 32)

    # Freeze some HTTP header names & values
    SERVER_SOFTWARE   = 'SERVER_SOFTWARE'.freeze
    SERVER_NAME       = 'SERVER_NAME'.freeze
    LOCALHOST         = 'localhost'.freeze
    HTTP_VERSION      = 'HTTP_VERSION'.freeze
    HTTP_1_0          = 'HTTP/1.0'.freeze
    REMOTE_ADDR       = 'REMOTE_ADDR'.freeze
    FORWARDED_FOR     = 'HTTP_X_FORWARDED_FOR'.freeze
    CONTENT_LENGTH    = 'CONTENT_LENGTH'.freeze
    CONNECTION        = 'HTTP_CONNECTION'.freeze
    KEEP_ALIVE_REGEXP = /\bkeep-alive\b/i.freeze
    CLOSE_REGEXP      = /\bclose\b/i.freeze
    
    # Freeze some Rack header names
    RACK_INPUT        = 'rack.input'.freeze
    RACK_VERSION      = 'rack.version'.freeze
    RACK_ERRORS       = 'rack.errors'.freeze
    RACK_MULTITHREAD  = 'rack.multithread'.freeze
    RACK_MULTIPROCESS = 'rack.multiprocess'.freeze
    RACK_RUN_ONCE     = 'rack.run_once'.freeze
    ASYNC_CALLBACK    = 'async.callback'.freeze
    ASYNC_CLOSE       = 'async.close'.freeze

    # CGI-like request environment variables
    attr_reader :env

    # Unparsed data of the request
    attr_reader :data
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,6 @@
     HTTP_VERSION      = 'HTTP_VERSION'.freeze
     HTTP_1_0          = 'HTTP/1.0'.freeze
     REMOTE_ADDR       = 'REMOTE_ADDR'.freeze
-    FORWARDED_FOR     = 'HTTP_X_FORWARDED_FOR'.freeze
     CONTENT_LENGTH    = 'CONTENT_LENGTH'.freeze
     CONNECTION        = 'HTTP_CONNECTION'.freeze
     KEEP_ALIVE_REGEXP = /\bkeep-alive\b/i.freeze
@@ -123,10 +122,6 @@
       @env[REMOTE_ADDR] = address
     end
 
-    def forwarded_for
-      @env[FORWARDED_FOR]
-    end
-
     def threaded=(value)
       @env[RACK_MULTITHREAD] = value
     end
```
