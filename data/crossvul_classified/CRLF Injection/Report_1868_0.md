# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in ruby
**Pair ID:** 1868_0
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1868_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```ruby
Lines 98-138 of the vulnerable file.

    #
    # Or name, value pair:
    #
    #  Field.new("field-name", "value")
    #
    # Or a name by itself:
    #
    #  Field.new("field-name")
    #
    # Note, does not want a terminating carriage return.  Returns
    # self appropriately parsed.  If value is not a string, then
    # it will be passed through as is, for example, content-type
    # field can accept an array with the type and a hash of
    # parameters:
    #
    #  Field.new('content-type', ['text', 'plain', {:charset => 'UTF-8'}])
    def initialize(name, value = nil, charset = 'utf-8')
      case
      when name =~ /:/                  # Field.new("field-name: field data")
        @charset = value.blank? ? charset : value
        @name, @value = split(name)
      when name !~ /:/ && value.blank?  # Field.new("field-name")
        @name = name
        @value = nil
        @charset = charset
      else                              # Field.new("field-name", "value")
        @name = name
        @value = value
        @charset = charset
      end
      return self
    end

    def field=(value)
      @field = value
    end

    def field
      @field ||= create_field(@name, @value, @charset)
    end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,7 +115,8 @@
       case
       when name =~ /:/                  # Field.new("field-name: field data")
         @charset = value.blank? ? charset : value
-        @name, @value = split(name)
+        @name = name[FIELD_PREFIX]
+        @raw_value = name
       when name !~ /:/ && value.blank?  # Field.new("field-name")
         @name = name
         @value = nil
@@ -125,7 +126,7 @@
         @value = value
         @charset = charset
       end
-      return self
+      @name = FIELD_NAME_MAP[@name.to_s.downcase] || @name
     end
 
     def field=(value)
@@ -133,11 +134,12 @@
     end
 
     def field
+      _, @value = split(@raw_value) if @raw_value && !@value
       @field ||= create_field(@name, @value, @charset)
     end
 
     def name
-      FIELD_NAME_MAP[@name.to_s.downcase] || @name
+      @name
     end
 
     def value
@@ -198,7 +200,21 @@
       STDERR.puts "WARNING: Could not parse (and so ignoring) '#{raw_field}'"
     end
 
+    # 2.2.3. Long Header Fields
+    #
+    #  The process of moving from this folded multiple-line representation
+    #  of a header field to its single line representation is called
+    #  "unfolding". Unfolding is accomplished by simply removing any CRLF
+    #  that is immediately followed by WSP.  Each header field should be
+    #  treated in its unfolded form for further syntactic and semantic
+    #  evaluation.
+    def unfold(string)
+      string.gsub(/[\r\n \t]+/m, ' ')
+    end
+
     def create_field(name, value, charset)
+      value = unfold(value) if value.is_a?(String) || value.is_a?(Mail::Multibyte::Chars)
+
       begin
         new_field(name, value, charset)
       rescue Mail::Field::ParseError => e
```
