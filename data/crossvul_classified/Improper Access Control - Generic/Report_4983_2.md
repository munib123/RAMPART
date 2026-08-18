# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 1-25 of the vulnerable file.

require 'openssl'
require 'cgi'
require 'puppet/network/http/handler'
require 'puppet/util/ssl'

class Puppet::Network::HTTP::RackREST
  include Puppet::Network::HTTP::Handler

  ContentType = 'Content-Type'.freeze

  CHUNK_SIZE = 8192

  class RackFile
    def initialize(file)
      @file = file
    end

    def each
      while chunk = @file.read(CHUNK_SIZE)
        yield chunk
      end
    end

    def close
      @file.close
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 require 'cgi'
 require 'puppet/network/http/handler'
 require 'puppet/util/ssl'
+require 'uri'
 
 class Puppet::Network::HTTP::RackREST
   include Puppet::Network::HTTP::Handler
@@ -79,7 +80,15 @@
 
   # what path was requested? (this is, without any query parameters)
   def path(request)
-    request.path
+    # The value that Passenger provides for 'path' is escaped
+    # (URL percent-encoded), see
+    # https://github.com/phusion/passenger/blob/release-5.0.26/src/apache2_module/Hooks.cpp#L885
+    # for the implementation as hooked up to an Apache web server.  Code
+    # in the indirector / HTTP layer which consumes this path, however, assumes
+    # that it has already been unescaped, so it is unescaped here.
+    if request.path
+      URI.unescape(request.path)
+    end
   end
 
   # return the request body
```
