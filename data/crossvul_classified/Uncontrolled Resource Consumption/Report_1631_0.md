# CrossVul Fix Pair: Uncontrolled Resource Consumption in ruby
**Pair ID:** 1631_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1631_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```ruby
Lines 265-305 of the vulnerable file.

      #   unique.
      #
      # @return [ ObjectId ] The new object id.
      #
      # @since 2.0.0
      def from_time(time, options = {})
        from_data(options[:unique] ? @@generator.next_object_id(time.to_i) : [ time.to_i ].pack("Nx8"))
      end

      # Determine if the provided string is a legal object id.
      #
      # @example Is the string a legal object id?
      #   BSON::ObjectId.legal?(string)
      #
      # @param [ String ] The string to check.
      #
      # @return [ true, false ] If the string is legal.
      #
      # @since 2.0.0
      def legal?(string)
        string.to_s =~ /^[0-9a-f]{24}$/i ? true : false
      end

      # Executes the provided block only if the size of the provided object is
      # 12. Used in legacy id repairs.
      #
      # @example Execute in a repairing block.
      #   BSON::ObjectId.repair("test") { obj }
      #
      # @param [ String, Array ] object The object to repair.
      #
      # @raise [ Invalid ] If the array is not 12 elements.
      #
      # @return [ String ] The result of the block.
      #
      # @since 2.0.0
      def repair(object)
        if object.size == 12
          block_given? ? yield(object) : object
        else
          raise Invalid.new("#{object.inspect} is not a valid object id.")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -282,7 +282,7 @@
       #
       # @since 2.0.0
       def legal?(string)
-        string.to_s =~ /^[0-9a-f]{24}$/i ? true : false
+        string.to_s =~ /\A[0-9a-f]{24}\z/i ? true : false
       end
 
       # Executes the provided block only if the size of the provided object is
```
