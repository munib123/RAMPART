# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 5753_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5753_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

module I18n
  # Handles exceptions raised in the backend. All exceptions except for
  # MissingTranslationData exceptions are re-thrown. When a MissingTranslationData
  # was caught the handler returns an error message string containing the key/scope.
  # Note that the exception handler is not called when the option :throw was given.
  class ExceptionHandler
    include Module.new {
      def call(exception, locale, key, options)
        if exception.is_a?(MissingTranslation)
          options[:rescue_format] == :html ? exception.html_message : exception.message
        elsif exception.is_a?(Exception)
          raise exception
        else
          throw :exception, exception
        end
      end
    }
  end

  class ArgumentError < ::ArgumentError; end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
+require 'cgi'
+
 module I18n
   # Handles exceptions raised in the backend. All exceptions except for
   # MissingTranslationData exceptions are re-thrown. When a MissingTranslationData
@@ -7,7 +9,19 @@
     include Module.new {
       def call(exception, locale, key, options)
         if exception.is_a?(MissingTranslation)
-          options[:rescue_format] == :html ? exception.html_message : exception.message
+          #
+          # TODO: this block is to be replaced by `exception.message` when
+          # rescue_format is removed
+          if options[:rescue_format] == :html
+            if @rescue_format_deprecation
+              $stderr.puts "[DEPRECATED] I18n's :recue_format option will be removed from a future release. All exception messages will be plain text. If you need the exception handler to return an html format please set or pass a custom exception handler."
+              @rescue_format_deprecation = true
+            end
+            exception.html_message
+          else
+            exception.message
+          end
+
         elsif exception.is_a?(Exception)
           raise exception
         else
@@ -45,8 +59,9 @@
       end
 
       def html_message
-        key = keys.last.to_s.gsub('_', ' ').gsub(/\b('?[a-z])/) { $1.capitalize }
-        %(<span class="translation_missing" title="translation missing: #{keys.join('.')}">#{key}</span>)
+        key  = CGI.escape_html titleize(keys.last)
+        path = CGI.escape_html keys.join('.')
+        %(<span class="translation_missing" title="translation missing: #{path}">#{key}</span>)
       end
 
       def keys
@@ -62,6 +77,13 @@
 
       def to_exception
         MissingTranslationData.new(locale, key, options)
+      end
+
+      protected
+
+      # TODO : remove when #html_message is removed
+      def titleize(key)
+        key.to_s.gsub('_', ' ').gsub(/\b('?[a-z])/) { $1.capitalize }
       end
     end
 
```
