# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1755_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1755_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-36 of the vulnerable file.

module Rails
  module Html
    XPATHS_TO_REMOVE = %w{.//script .//form comment()}

    class Sanitizer # :nodoc:
      def sanitize(html, options = {})
        raise NotImplementedError, "subclasses must implement sanitize method."
      end

      private

      def remove_xpaths(node, xpaths)
        node.xpath(*xpaths).remove
        node
      end
    end

    # === Rails::Html::FullSanitizer
    # Removes all tags but strips out scripts, forms and comments.
    #
    # full_sanitizer = Rails::Html::FullSanitizer.new
    # full_sanitizer.sanitize("<b>Bold</b> no more!  <a href='more.html'>See more here</a>...")
    # # => Bold no more!  See more here...
    class FullSanitizer < Sanitizer
      def sanitize(html, options = {})
        return unless html
        return html if html.empty?

        Loofah.fragment(html).tap do |fragment|
          remove_xpaths(fragment, XPATHS_TO_REMOVE)
        end.text(options)
      end
    end

    # === Rails::Html::LinkSanitizer
    # Removes a tags and href attributes leaving only the link text
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,10 @@
         node.xpath(*xpaths).remove
         node
       end
+
+      def properly_encode(fragment, options)
+        fragment.xml? ? fragment.to_xml(options) : fragment.to_html(options)
+      end
     end
 
     # === Rails::Html::FullSanitizer
@@ -26,9 +30,12 @@
         return unless html
         return html if html.empty?
 
-        Loofah.fragment(html).tap do |fragment|
-          remove_xpaths(fragment, XPATHS_TO_REMOVE)
-        end.text(options)
+        loofah_fragment = Loofah.fragment(html)
+
+        remove_xpaths(loofah_fragment, XPATHS_TO_REMOVE)
+        loofah_fragment.scrub!(TextOnlyScrubber.new)
+
+        properly_encode(loofah_fragment, encoding: 'UTF-8')
       end
     end
 
@@ -140,10 +147,6 @@
       def allowed_attributes(options)
         options[:attributes] || self.class.allowed_attributes
       end
-
-      def properly_encode(fragment, options)
-        fragment.xml? ? fragment.to_xml(options) : fragment.to_html(options)
-      end
     end
   end
 end
```
