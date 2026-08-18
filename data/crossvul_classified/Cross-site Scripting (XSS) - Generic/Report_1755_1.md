# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1755_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1755_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 152-173 of the vulnerable file.


    # === Rails::Html::TargetScrubber
    #
    # Where Rails::Html::PermitScrubber picks out tags and attributes to permit in
    # sanitization, Rails::Html::TargetScrubber targets them for removal.
    #
    # +tags=+
    # If set, elements included will be stripped.
    #
    # +attributes=+
    # If set, attributes included will be removed.
    class TargetScrubber < PermitScrubber
      def allowed_node?(node)
        !super
      end

      def scrub_attribute?(name)
        !super
      end
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,5 +169,25 @@
         !super
       end
     end
+
+    # === Rails::Html::TextOnlyScrubber
+    #
+    # Rails::Html::TextOnlyScrubber allows you to permit text nodes.
+    #
+    # Unallowed elements will be stripped, i.e. element is removed but its subtree kept.
+    class TextOnlyScrubber < Loofah::Scrubber
+      def initialize
+        @direction = :bottom_up
+      end
+
+      def scrub(node)
+        if node.text?
+          CONTINUE
+        else
+          node.before node.children
+          node.remove
+        end
+      end
+    end
   end
 end
```
