# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 1754_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1754_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 80-120 of the vulnerable file.

    # === Examples
    # white_list_sanitizer = Rails::Html::WhiteListSanitizer.new
    #
    # Sanitize css doesn't take options
    # white_list_sanitizer.sanitize_css('background-color: #000;')
    #
    # Default: sanitize via a extensive white list of allowed elements
    # white_list_sanitizer.sanitize(@article.body)
    #
    # White list via the supplied tags and attributes
    # white_list_sanitizer.sanitize(@article.body, tags: %w(table tr td),
    # attributes: %w(id class style))
    #
    # White list via a custom scrubber
    # white_list_sanitizer.sanitize(@article.body, scrubber: ArticleScrubber.new)
    class WhiteListSanitizer < Sanitizer
      class << self
        attr_accessor :allowed_tags
        attr_accessor :allowed_attributes
      end

      def initialize
        @permit_scrubber = PermitScrubber.new
      end

      def sanitize(html, options = {})
        return unless html
        return html if html.empty?

        loofah_fragment = Loofah.fragment(html)

        if scrubber = options[:scrubber]
          # No duck typing, Loofah ensures subclass of Loofah::Scrubber
          loofah_fragment.scrub!(scrubber)
        elsif allowed_tags(options) || allowed_attributes(options)
          @permit_scrubber.tags = allowed_tags(options)
          @permit_scrubber.attributes = allowed_attributes(options)
          loofah_fragment.scrub!(@permit_scrubber)
        else
          remove_xpaths(loofah_fragment, XPATHS_TO_REMOVE)
          loofah_fragment.scrub!(:strip)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,6 +97,10 @@
         attr_accessor :allowed_tags
         attr_accessor :allowed_attributes
       end
+      self.allowed_tags = Set.new(%w(strong em b i p code pre tt samp kbd var sub
+        sup dfn cite big small address hr br div span h1 h2 h3 h4 h5 h6 ul ol li dl dt dd abbr
+        acronym a img blockquote del ins))
+      self.allowed_attributes = Set.new(%w(href src width height alt cite datetime title class name xml:lang abbr))
 
       def initialize
         @permit_scrubber = PermitScrubber.new
```
