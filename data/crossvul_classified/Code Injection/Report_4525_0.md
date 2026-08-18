# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4525_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4525_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 89-130 of the vulnerable file.

    def build_media_type_list_directive(directive)
      return unless media_type_list = @config.directive_value(directive)
      if media_type_list && media_type_list.any?
        [
          symbol_to_hyphen_case(directive),
          media_type_list.uniq
        ].join(" ")
      end
    end

    # Private: builds a string that represents one directive in a minified form.
    #
    # directive_name - a symbol representing the various ALL_DIRECTIVES
    #
    # Returns a string representing a directive.
    def build_source_list_directive(directive)
      source_list = @config.directive_value(directive)
      if source_list != OPT_OUT && source_list && source_list.any?
        minified_source_list = minify_source_list(directive, source_list).join(" ")

        if minified_source_list.include?(";")
          Kernel.warn("#{directive} contains a ; in '#{minified_source_list}' which will raise an error in future versions. It has been replaced with a blank space.")
        end

        escaped_source_list = minified_source_list.gsub(";", " ")
        [symbol_to_hyphen_case(directive), escaped_source_list].join(" ").strip
      end
    end

    # If a directive contains *, all other values are omitted.
    # If a directive contains 'none' but has other values, 'none' is ommitted.
    # Schemes are stripped (see http://www.w3.org/TR/CSP2/#match-source-expression)
    def minify_source_list(directive, source_list)
      source_list = source_list.compact
      if source_list.include?(STAR)
        keep_wildcard_sources(source_list)
      else
        source_list = populate_nonces(directive, source_list)
        source_list = reject_all_values_if_none(source_list)

        unless directive == REPORT_URI || @preserve_schemes
          source_list = strip_source_schemes(source_list)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,11 +106,11 @@
       if source_list != OPT_OUT && source_list && source_list.any?
         minified_source_list = minify_source_list(directive, source_list).join(" ")
 
-        if minified_source_list.include?(";")
-          Kernel.warn("#{directive} contains a ; in '#{minified_source_list}' which will raise an error in future versions. It has been replaced with a blank space.")
-        end
-
-        escaped_source_list = minified_source_list.gsub(";", " ")
+        if minified_source_list =~ /(\n|;)/
+          Kernel.warn("#{directive} contains a #{$1} in #{minified_source_list.inspect} which will raise an error in future versions. It has been replaced with a blank space.")
+        end
+
+        escaped_source_list = minified_source_list.gsub(/[\n;]/, " ")
         [symbol_to_hyphen_case(directive), escaped_source_list].join(" ").strip
       end
     end
```
