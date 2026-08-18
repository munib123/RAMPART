# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1754_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1754_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 83-123 of the vulnerable file.

        !@attributes.include?(name)
      end

      def keep_node?(node)
        if @tags
          allowed_node?(node)
        else
          Loofah::HTML5::Scrub.allowed_element?(node.name)
        end
      end

      def scrub_node(node)
        node.before(node.children) # strip
        node.remove
      end

      def scrub_attributes(node)
        if @attributes
          node.attribute_nodes.each do |attr|
            attr.remove if scrub_attribute?(attr.name)
          end

          scrub_css_attribute(node)
        else
          Loofah::HTML5::Scrub.scrub_attributes(node)
        end
      end

      def scrub_css_attribute(node)
        if Loofah::HTML5::Scrub.respond_to?(:scrub_css_attribute)
          Loofah::HTML5::Scrub.scrub_css_attribute(node)
        else
          style = node.attributes['style']
          style.value = Loofah::HTML5::Scrub.scrub_css(style.value) if style
        end
      end

      def validate!(var, name)
        if var && !var.is_a?(Enumerable)
          raise ArgumentError, "You should pass :#{name} as an Enumerable"
        end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,6 +100,7 @@
         if @attributes
           node.attribute_nodes.each do |attr|
             attr.remove if scrub_attribute?(attr.name)
+            scrub_attribute(node, attr)
           end
 
           scrub_css_attribute(node)
@@ -122,6 +123,30 @@
           raise ArgumentError, "You should pass :#{name} as an Enumerable"
         end
         var
+      end
+
+      def scrub_attribute(node, attr_node)
+        attr_name = if attr_node.namespace
+                      "#{attr_node.namespace.prefix}:#{attr_node.node_name}"
+                    else
+                      attr_node.node_name
+                    end
+
+        if Loofah::HTML5::WhiteList::ATTR_VAL_IS_URI.include?(attr_name)
+          # this block lifted nearly verbatim from HTML5 sanitization
+          val_unescaped = CGI.unescapeHTML(attr_node.value).gsub(Loofah::HTML5::Scrub::CONTROL_CHARACTERS,'').downcase
+          if val_unescaped =~ /^[a-z0-9][-+.a-z0-9]*:/ && ! Loofah::HTML5::WhiteList::ALLOWED_PROTOCOLS.include?(val_unescaped.split(Loofah::HTML5::WhiteList::PROTOCOL_SEPARATOR)[0])
+            attr_node.remove
+          end
+        end
+        if Loofah::HTML5::WhiteList::SVG_ATTR_VAL_ALLOWS_REF.include?(attr_name)
+          attr_node.value = attr_node.value.gsub(/url\s*\(\s*[^#\s][^)]+?\)/m, ' ') if attr_node.value
+        end
+        if Loofah::HTML5::WhiteList::SVG_ALLOW_LOCAL_HREF.include?(node.name) && attr_name == 'xlink:href' && attr_node.value =~ /^\s*[^#\s].*/m
+          attr_node.remove
+        end
+
+        node.remove_attribute(attr_node.name) if attr_name == 'src' && attr_node.value !~ /[^[:space:]]/
       end
     end
 
```
