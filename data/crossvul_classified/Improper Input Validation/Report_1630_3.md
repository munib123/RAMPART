# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1630_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1630_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

require "digest/md5"
require "socket"

module Moped
  module BSON
    class ObjectId

      # Formatting string for outputting an ObjectId.
      @@string_format = ("%02x" * 12).freeze

      attr_reader :data

      class << self
        def from_string(string)
          raise Errors::InvalidObjectId.new(string) unless legal?(string)
          data = []
          12.times { |i| data << string[i*2, 2].to_i(16) }
          new data
        end

        def legal?(str)
          !!str.match(/^[0-9a-f]{24}$/i)
        end
      end

      def initialize(data = nil, time = nil)
        if data
          @data = data
        elsif time
          @data = @@generator.generate(time.to_i)
        else
          @data = @@generator.next
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,29 +8,31 @@
       # Formatting string for outputting an ObjectId.
       @@string_format = ("%02x" * 12).freeze
 
-      attr_reader :data
-
       class << self
         def from_string(string)
           raise Errors::InvalidObjectId.new(string) unless legal?(string)
-          data = []
+          data = ""
           12.times { |i| data << string[i*2, 2].to_i(16) }
-          new data
+          from_data data
+        end
+
+        def from_time(time)
+          from_data @@generator.generate(time.to_i)
         end
 
         def legal?(str)
-          !!str.match(/^[0-9a-f]{24}$/i)
+          !!str.match(/\A\h{24}\Z/i)
+        end
+
+        def from_data(data)
+          id = allocate
+          id.instance_variable_set :@data, data
+          id
         end
       end
 
-      def initialize(data = nil, time = nil)
-        if data
-          @data = data
-        elsif time
-          @data = @@generator.generate(time.to_i)
-        else
-          @data = @@generator.next
-        end
+      def data
+        @data ||= @@generator.next
       end
 
       def ==(other)
@@ -43,28 +45,27 @@
       end
 
       def to_s
-        @@string_format % data
+        @@string_format % data.unpack("C12")
       end
 
       # Return the UTC time at which this ObjectId was generated. This may
       # be used instread of a created_at timestamp since this information
       # is always encoded in the object id.
       def generation_time
-        Time.at(@data.pack("C4").unpack("N")[0]).utc
+        Time.at(data.unpack("N")[0]).utc
       end
 
       class << self
         def __bson_load__(io)
-          new io.read(12).unpack('C*')
+          from_data(io.read(12))
         end
-
       end
 
       def __bson_dump__(io, key)
         io << Types::OBJECT_ID
         io << key
         io << NULL_BYTE
-        io << data.pack('C12')
+        io << data
       end
 
       # @api private
@@ -72,49 +73,28 @@
         def initialize
           # Generate and cache 3 bytes of identifying information from the current
           # machine.
-          @machine_id = Digest::MD5.digest(Socket.gethostname).unpack("C3")
+          @machine_id = Digest::MD5.digest(Socket.gethostname).unpack("N")[0]
 
           @mutex = Mutex.new
-          @last_timestamp = nil
           @counter = 0
         end
 
-        # Return object id data based on the current time, incrementing a
-        # counter for object ids generated in the same second.
+        # Return object id data based on the current time, incrementing the
+        # object id counter.
         def next
-          now = Time.new.to_i
-
-          counter = @mutex.synchronize do
-            last_timestamp, @last_timestamp = @last_timestamp, now
-
-            if last_timestamp == now
-              @counter += 1
-            else
-              @counter = 0
-            end
+          @mutex.lock
+          begin
+            counter = @counter = (@counter + 1) % 0xFFFFFF
+          ensure
+            @mutex.unlock rescue nil
           end
 
-          generate(now, counter)
+          generate(Time.new.to_i, counter)
         end
 
-        # Generate object id data for a given time using the provided +inc+.
-        def generate(time, inc = 0)
-          pid = Process.pid % 0xFFFF
-
-          [
-            time >> 24 & 0xFF, # 4 bytes time (network order)
-            time >> 16 & 0xFF,
-            time >> 8  & 0xFF,
-            time       & 0xFF,
-            @machine_id[0],   # 3 bytes machine
-            @machine_id[1],
-            @machine_id[2],
-            pid  >> 8  & 0xFF, # 2 bytes process id
-            pid        & 0xFF,
-            inc  >> 16 & 0xFF, # 3 bytes increment
-            inc  >> 8  & 0xFF,
-            inc        & 0xFF,
-          ]
+        # Generate object id data for a given time using the provided +counter+.
+        def generate(time, counter = 0)
+          [time, @machine_id, Process.pid, counter << 8].pack("N NX lXX NX")
         end
       end
 
```
