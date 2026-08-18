# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1756_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1756_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 43-83 of the vulnerable file.

    #
    # See the documentation for Nokogiri::XML::Node to understand what's possible
    # with nodes: http://nokogiri.org/Nokogiri/XML/Node.html
    class PermitScrubber < Loofah::Scrubber
      attr_reader :tags, :attributes

      def initialize
        @direction = :bottom_up
        @tags, @attributes = nil, nil
      end

      def tags=(tags)
        @tags = validate!(tags, :tags)
      end

      def attributes=(attributes)
        @attributes = validate!(attributes, :attributes)
      end

      def scrub(node)
        return CONTINUE if skip_node?(node)

        unless keep_node?(node)
          return STOP if scrub_node(node) == STOP
        end

        scrub_attributes(node)
      end

      protected

      def allowed_node?(node)
        @tags.include?(node.name)
      end

      def skip_node?(node)
        node.text? || node.cdata?
      end

      def scrub_attribute?(name)
        !@attributes.include?(name)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,11 @@
       end
 
       def scrub(node)
+        if node.cdata?
+          text = node.document.create_text_node node.text
+          node.replace text
+          return CONTINUE
+        end
         return CONTINUE if skip_node?(node)
 
         unless keep_node?(node)
@@ -76,7 +81,7 @@
       end
 
       def skip_node?(node)
-        node.text? || node.cdata?
+        node.text?
       end
 
       def scrub_attribute?(name)
```
