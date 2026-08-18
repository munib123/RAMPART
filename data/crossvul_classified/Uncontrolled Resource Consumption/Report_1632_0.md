# CrossVul Fix Pair: Uncontrolled Resource Consumption in ruby
**Pair ID:** 1632_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1632_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```ruby
Lines 2-42 of the vulnerable file.

#
# The core namespace for all BSON related behaviour.
#
# @since 0.0.0
module BSON

  # Constant for binary string encoding.
  #
  # @since 2.0.0
  BINARY = "BINARY".freeze

  # Constant for bson types that don't actually serialize a value.
  #
  # @since 2.0.0
  NO_VALUE = "".force_encoding(BINARY).freeze

  # Constant for a null byte (0x00).
  #
  # @since 2.0.0
  NULL_BYTE = 0.chr.force_encoding(BINARY).freeze
end

require "bson/registry"
require "bson/document"
require "bson/version"

# Determine if we are using JRuby or not.
#
# @example Are we running with JRuby?
#   jruby?
#
# @return [ true, false ] If JRuby is our vm.
#
# @since 2.0.0
def jruby?
  RUBY_ENGINE == "jruby"
end

# If we are using JRuby, attempt to load the Java extensions, if we are using
# MRI or Rubinius, attempt to load the C extenstions. If either of these fail,
# we revert back to a pure Ruby implementation of the Buffer class.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,11 @@
   #
   # @since 2.0.0
   NULL_BYTE = 0.chr.force_encoding(BINARY).freeze
+
+  # Constant for UTF-8 string encoding.
+  #
+  # @since 2.0.0
+  UTF8 = "UTF-8".freeze
 end
 
 require "bson/registry"
```
