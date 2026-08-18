# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 4511_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4511_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 57-97 of the vulnerable file.

      :elements => [],

      # HTML parsing options to pass to Nokogumbo.
      # https://github.com/rubys/nokogumbo/tree/v2.0.1#parsing-options
      :parser_options => {},

      # URL handling protocols to allow in specific attributes. By default, no
      # protocols are allowed. Use :relative in place of a protocol if you want
      # to allow relative URLs sans protocol.
      :protocols => {},

      # If this is true, Sanitize will remove the contents of any filtered
      # elements in addition to the elements themselves. By default, Sanitize
      # leaves the safe parts of an element's contents behind when the element
      # is removed.
      #
      # If this is an Array or Set of element names, then only the contents of
      # the specified elements (when filtered) will be removed, and the contents
      # of all other filtered elements will be left behind.
      :remove_contents => %w[
        iframe noembed noframes noscript script style
      ],

      # Transformers allow you to filter or alter nodes using custom logic. See
      # README.md for details and examples.
      :transformers => [],

      # Elements which, when removed, should have their contents surrounded by
      # values specified with `before` and `after` keys to preserve readability.
      # For example, `foo<div>bar</div>baz` will become 'foo bar baz' when the
      # <div> is removed.
      :whitespace_elements => {
        'address'    => { :before => ' ', :after => ' ' },
        'article'    => { :before => ' ', :after => ' ' },
        'aside'      => { :before => ' ', :after => ' ' },
        'blockquote' => { :before => ' ', :after => ' ' },
        'br'         => { :before => ' ', :after => ' ' },
        'dd'         => { :before => ' ', :after => ' ' },
        'div'        => { :before => ' ', :after => ' ' },
        'dl'         => { :before => ' ', :after => ' ' },
        'dt'         => { :before => ' ', :after => ' ' },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
       # the specified elements (when filtered) will be removed, and the contents
       # of all other filtered elements will be left behind.
       :remove_contents => %w[
-        iframe noembed noframes noscript script style
+        iframe math noembed noframes noscript plaintext script style svg xmp
       ],
 
       # Transformers allow you to filter or alter nodes using custom logic. See
```
