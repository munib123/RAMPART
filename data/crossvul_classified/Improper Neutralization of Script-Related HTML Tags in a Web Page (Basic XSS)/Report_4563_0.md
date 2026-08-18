# CrossVul Fix Pair: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) in ruby
**Pair ID:** 4563_0
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**CWE:** CWE-80
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4563_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - This may allow such characters to be treated as control characters, which are executed client-side in the context of the user's session.

## Vulnerable Code
```ruby
Lines 1-35 of the vulnerable file.

# frozen_string_literal: true

require "action_view/helpers/tag_helper"

module ActionView
  module Helpers #:nodoc:
    module JavaScriptHelper
      JS_ESCAPE_MAP = {
        '\\'    => '\\\\',
        "</"    => '<\/',
        "\r\n"  => '\n',
        "\n"    => '\n',
        "\r"    => '\n',
        '"'     => '\\"',
        "'"     => "\\'"
      }

      JS_ESCAPE_MAP[(+"\342\200\250").force_encoding(Encoding::UTF_8).encode!] = "&#x2028;"
      JS_ESCAPE_MAP[(+"\342\200\251").force_encoding(Encoding::UTF_8).encode!] = "&#x2029;"

      # Escapes carriage returns and single and double quotes for JavaScript segments.
      #
      # Also available through the alias j(). This is particularly helpful in JavaScript
      # responses, like:
      #
      #   $('some_element').replaceWith('<%= j render 'some/element_template' %>');
      def escape_javascript(javascript)
        javascript = javascript.to_s
        if javascript.empty?
          result = ""
        else
          result = javascript.gsub(/(\\|<\/|\r\n|\342\200\250|\342\200\251|[\n\r"'])/u, JS_ESCAPE_MAP)
        end
        javascript.html_safe? ? result.html_safe : result
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,9 @@
         "\n"    => '\n',
         "\r"    => '\n',
         '"'     => '\\"',
-        "'"     => "\\'"
+        "'"     => "\\'",
+        "`"     => "\\`",
+        "$"     => "\\$"
       }
 
       JS_ESCAPE_MAP[(+"\342\200\250").force_encoding(Encoding::UTF_8).encode!] = "&#x2028;"
@@ -29,7 +31,7 @@
         if javascript.empty?
           result = ""
         else
-          result = javascript.gsub(/(\\|<\/|\r\n|\342\200\250|\342\200\251|[\n\r"'])/u, JS_ESCAPE_MAP)
+          result = javascript.gsub(/(\\|<\/|\r\n|\342\200\250|\342\200\251|[\n\r"']|[`]|[$])/u, JS_ESCAPE_MAP)
         end
         javascript.html_safe? ? result.html_safe : result
       end
```
