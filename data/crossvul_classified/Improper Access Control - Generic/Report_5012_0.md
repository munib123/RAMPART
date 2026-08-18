# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5012_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5012_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module Safemode
  class Blankslate
    @@allow_instance_methods = ['class', 'inspect', 'methods', 'respond_to?', 'respond_to_missing?', 'to_s', 'instance_variable_get']
    @@allow_class_methods    = ['methods', 'new', 'name', 'inspect', '<', 'ancestors', '=='] # < needed in Rails Object#subclasses_of

    silently { undef_methods(*instance_methods.map(&:to_s) - @@allow_instance_methods) }
    class << self
      silently { undef_methods(*instance_methods.map(&:to_s) - @@allow_class_methods) }

      def method_added(name) end # ActiveSupport needs this

      def inherited(subclass)
        subclass.init_allowed_methods(@allowed_methods)
      end

      def init_allowed_methods(allowed_methods)
        @allowed_methods = allowed_methods
      end

      def allowed_methods
        @allowed_methods ||= []
      end

      def allow(*names)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 module Safemode
   class Blankslate
-    @@allow_instance_methods = ['class', 'inspect', 'methods', 'respond_to?', 'respond_to_missing?', 'to_s', 'instance_variable_get']
-    @@allow_class_methods    = ['methods', 'new', 'name', 'inspect', '<', 'ancestors', '=='] # < needed in Rails Object#subclasses_of
+    @@allow_instance_methods = ['class', 'methods', 'respond_to?', 'respond_to_missing?', 'to_s', 'instance_variable_get']
+    @@allow_class_methods    = ['methods', 'new', 'name', '<', 'ancestors', '=='] # < needed in Rails Object#subclasses_of
 
     silently { undef_methods(*instance_methods.map(&:to_s) - @@allow_instance_methods) }
     class << self
```
