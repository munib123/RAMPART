# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 2519_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2519_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

require 'redis/store/ttl'
require 'redis/store/interface'
require 'redis/store/redis_version'

class Redis
  class Store < self
    include Ttl, Interface, RedisVersion

    def initialize(options = { })
      super
      _extend_marshalling options
      _extend_namespace   options
    end

    def reconnect
      @client.reconnect
    end

    def to_s
      h = @client.host
      "Redis Client connected to #{/:/ =~ h ? '['+h+']' : h}:#{@client.port} against DB #{@client.db}"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,10 @@
+require 'redis'
+require 'redis/store/factory'
+require 'redis/distributed_store'
+require 'redis/store/namespace'
+require 'redis/store/serialization'
+require 'redis/store/version'
+require 'redis/store/redis_version'
 require 'redis/store/ttl'
 require 'redis/store/interface'
 require 'redis/store/redis_version'
@@ -8,6 +15,24 @@
 
     def initialize(options = { })
       super
+
+      unless options[:marshalling].nil?
+        puts %(
+          DEPRECATED: You are passing the :marshalling option, which has been
+          replaced with `serializer: Marshal` to support pluggable serialization
+          backends. To disable serialization (much like disabling marshalling),
+          pass `serializer: nil` in your configuration.
+
+          The :marshalling option will be removed for redis-store 2.0.
+        )
+      end
+
+      @serializer = options.key?(:serializer) ? options[:serializer] : Marshal
+
+      unless options[:marshalling].nil?
+        @serializer = options[:marshalling] ? Marshal : nil
+      end
+
       _extend_marshalling options
       _extend_namespace   options
     end
@@ -23,8 +48,7 @@
 
     private
       def _extend_marshalling(options)
-        @marshalling = !(options[:marshalling] === false) # HACK - TODO delegate to Factory
-        extend Marshalling if @marshalling
+        extend Serialization unless @serializer.nil?
       end
 
       def _extend_namespace(options)
```
