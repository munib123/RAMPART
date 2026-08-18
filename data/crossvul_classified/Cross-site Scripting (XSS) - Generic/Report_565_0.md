# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 565_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `565_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 136-176 of the vulnerable file.

                      "#{attr_node.namespace.prefix}:#{attr_node.node_name}"
                    else
                      attr_node.node_name
                    end

        if Loofah::HTML5::WhiteList::ATTR_VAL_IS_URI.include?(attr_name)
          # this block lifted nearly verbatim from HTML5 sanitization
          val_unescaped = CGI.unescapeHTML(attr_node.value).gsub(Loofah::HTML5::Scrub::CONTROL_CHARACTERS,'').downcase
          if val_unescaped =~ /^[a-z0-9][-+.a-z0-9]*:/ && ! Loofah::HTML5::WhiteList::ALLOWED_PROTOCOLS.include?(val_unescaped.split(Loofah::HTML5::WhiteList::PROTOCOL_SEPARATOR)[0])
            attr_node.remove
          end
        end
        if Loofah::HTML5::WhiteList::SVG_ATTR_VAL_ALLOWS_REF.include?(attr_name)
          attr_node.value = attr_node.value.gsub(/url\s*\(\s*[^#\s][^)]+?\)/m, ' ') if attr_node.value
        end
        if Loofah::HTML5::WhiteList::SVG_ALLOW_LOCAL_HREF.include?(node.name) && attr_name == 'xlink:href' && attr_node.value =~ /^\s*[^#\s].*/m
          attr_node.remove
        end

        node.remove_attribute(attr_node.name) if attr_name == 'src' && attr_node.value !~ /[^[:space:]]/
      end
    end

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,6 +153,8 @@
         end
 
         node.remove_attribute(attr_node.name) if attr_name == 'src' && attr_node.value !~ /[^[:space:]]/
+
+        Loofah::HTML5::Scrub.force_correct_attribute_escaping! node
       end
     end
 
```
