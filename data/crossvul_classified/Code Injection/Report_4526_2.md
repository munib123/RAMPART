# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4526_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4526_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 121-162 of the vulnerable file.

    # Private: builds a string that represents one directive in a minified form.
    #
    # directive_name - a symbol representing the various ALL_DIRECTIVES
    #
    # Returns a string representing a directive.
    def build_source_list_directive(directive)
      source_list = case directive
      when :child_src
        if supported_directives.include?(:child_src)
          @frame_src
        end
      when :frame_src
        unless supported_directives.include?(:child_src)
          @frame_src
        end
      else
        @config.directive_value(directive)
      end

      if source_list != OPT_OUT && source_list && source_list.any?
        normalized_source_list = minify_source_list(directive, source_list)
        [symbol_to_hyphen_case(directive), normalized_source_list].join(" ")
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
        end
        dedup_source_list(source_list)
      end
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,8 +138,14 @@
       end
 
       if source_list != OPT_OUT && source_list && source_list.any?
-        normalized_source_list = minify_source_list(directive, source_list)
-        [symbol_to_hyphen_case(directive), normalized_source_list].join(" ")
+        minified_source_list = minify_source_list(directive, source_list).join(" ")
+
+        if minified_source_list.include?(";")
+          Kernel.warn("#{directive} contains a ; in '#{minified_source_list}' which will raise an error in future versions. It has been replaced with a blank space.")
+        end
+
+        escaped_source_list = minified_source_list.gsub(";", " ")
+        [symbol_to_hyphen_case(directive), escaped_source_list].join(" ").strip
       end
     end
 
```
