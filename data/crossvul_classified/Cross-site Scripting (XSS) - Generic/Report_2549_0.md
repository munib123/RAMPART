# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 2549_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2549_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 579-619 of the vulnerable file.

    # Like \{#haml_tag}, `haml_tag_if` outputs directly to the buffer and its
    # return value should not be used. Use \{#capture_haml} if you need to use
    # its results as a string.
    #
    # @param condition The condition to test to determine whether to render
    #   the enclosing tag
    # @param tag Definition of the enclosing tag. See \{#haml_tag} for details
    #   (specifically the form that takes a block)
    def haml_tag_if(condition, *tag)
      if condition
        haml_tag(*tag){ yield }
      else
        yield
      end
      ErrorReturn.new("haml_tag_if")
    end

    # Characters that need to be escaped to HTML entities from user input
    HTML_ESCAPE = { '&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&#039;' }

    HTML_ESCAPE_REGEX = /[\"><&]/

    # Returns a copy of `text` with ampersands, angle brackets and quotes
    # escaped into HTML entities.
    #
    # Note that if ActionView is loaded and XSS protection is enabled
    # (as is the default for Rails 3.0+, and optional for version 2.3.5+),
    # this won't escape text declared as "safe".
    #
    # @param text [String] The string to sanitize
    # @return [String] The sanitized string
    def html_escape(text)
      text = text.to_s
      text.gsub(HTML_ESCAPE_REGEX, HTML_ESCAPE)
    end

    HTML_ESCAPE_ONCE_REGEX = /[\"><]|&(?!(?:[a-zA-Z]+|#(?:\d+|[xX][0-9a-fA-F]+));)/

    # Escapes HTML entities in `text`, but without escaping an ampersand
    # that is already part of an escaped entity.
    #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -596,7 +596,7 @@
     # Characters that need to be escaped to HTML entities from user input
     HTML_ESCAPE = { '&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&#039;' }
 
-    HTML_ESCAPE_REGEX = /[\"><&]/
+    HTML_ESCAPE_REGEX = /['"><&]/
 
     # Returns a copy of `text` with ampersands, angle brackets and quotes
     # escaped into HTML entities.
```
