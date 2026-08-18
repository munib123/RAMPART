# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4048_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4048_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 572-594 of the vulnerable file.


    define(:footnote_prefix, String, '', <<~EOF)
      Prefix used for footnote IDs

      This option can be used to set a prefix for footnote IDs. This is useful
      when rendering multiple documents into the same output file to avoid
      duplicate IDs. The prefix should only contain characters that are valid
      in an ID!

      Default: ''
      Used by: HTML
    EOF

    define(:remove_line_breaks_for_cjk, Boolean, false, <<~EOF)
      Specifies whether line breaks should be removed between CJK characters

      Default: false
      Used by: HTML converter
    EOF

  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -589,6 +589,16 @@
       Used by: HTML converter
     EOF
 
+    define(:forbidden_inline_options, Object, %w[template], <<~EOF) do |val|
+      Defines the options that may not be set using the {::options} extension
+
+      Default: template
+      Used by: HTML converter
+    EOF
+      val.map! {|item| item.kind_of?(String) ? str_to_sym(item) : item }
+      simple_array_validator(val, :forbidden_inline_options)
+    end
+
   end
 
 end
```
