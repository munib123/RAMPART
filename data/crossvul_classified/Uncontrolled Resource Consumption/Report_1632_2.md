# CrossVul Fix Pair: Uncontrolled Resource Consumption in ruby
**Pair ID:** 1632_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1632_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```ruby
Lines 1-40 of the vulnerable file.

# encoding: utf-8
module BSON

  # Injects behaviour for encoding and decoding string values to and from
  # raw bytes as specified by the BSON spec.
  #
  # @see http://bsonspec.org/#/specification
  #
  # @since 2.0.0
  module String

    # A string is type 0x02 in the BSON spec.
    #
    # @since 2.0.0
    BSON_TYPE = 2.chr.force_encoding(BINARY).freeze

    # Constant for UTF-8 string encoding.
    #
    # @since 2.0.0
    UTF8 = "UTF-8".freeze

    # Get the string as encoded BSON.
    #
    # @example Get the string as encoded BSON.
    #   "test".to_bson
    #
    # @raise [ EncodingError ] If the string is not UTF-8.
    #
    # @return [ String ] The encoded string.
    #
    # @see http://bsonspec.org/#/specification
    #
    # @since 2.0.0
    def to_bson
      (bytesize + 1).to_bson + to_bson_cstring
    end

    # Get the string as an encoded C string.
    #
    # @example Get the string as an encoded C string.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,11 +13,6 @@
     #
     # @since 2.0.0
     BSON_TYPE = 2.chr.force_encoding(BINARY).freeze
-
-    # Constant for UTF-8 string encoding.
-    #
-    # @since 2.0.0
-    UTF8 = "UTF-8".freeze
 
     # Get the string as encoded BSON.
     #
```
