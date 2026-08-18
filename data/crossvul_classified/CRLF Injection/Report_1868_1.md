# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in ruby
**Pair ID:** 1868_1
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1868_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```ruby
Lines 227-283 of the vulnerable file.

    def has_content_id?
      !fields.select { |f| f.responsible_for?('Content-ID') }.empty?
    end

    # Returns true if the header has a Date defined (empty or not)
    def has_date?
      !fields.select { |f| f.responsible_for?('Date') }.empty?
    end

    # Returns true if the header has a MIME version defined (empty or not)
    def has_mime_version?
      !fields.select { |f| f.responsible_for?('Mime-Version') }.empty?
    end

    private
    
    def raw_source=(val)
      @raw_source = val
    end
    
    # 2.2.3. Long Header Fields
    # 
    #  The process of moving from this folded multiple-line representation
    #  of a header field to its single line representation is called
    #  "unfolding". Unfolding is accomplished by simply removing any CRLF
    #  that is immediately followed by WSP.  Each header field should be
    #  treated in its unfolded form for further syntactic and semantic
    #  evaluation.
    def unfold(string)
      string.gsub(/#{CRLF}#{WSP}+/, ' ').gsub(/#{WSP}+/, ' ')
    end
    
    # Returns the header with all the folds removed
    def unfolded_header
      @unfolded_header ||= unfold(raw_source)
    end
    
    # Splits an unfolded and line break cleaned header into individual field
    # strings.
    def split_header
      self.fields = unfolded_header.split(CRLF)
    end
    
    def select_field_for(name)
      fields.select { |f| f.responsible_for?(name) }
    end
    
    def limited_field?(name)
      LIMITED_FIELDS.include?(name.to_s.downcase)
    end

    # Enumerable support; yield each field in order to the block if there is one,
    # or return an Enumerator for them if there isn't.
    def each( &block )
      return self.fields.each( &block ) if block
      self.fields.each
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,27 +244,10 @@
       @raw_source = val
     end
     
-    # 2.2.3. Long Header Fields
-    # 
-    #  The process of moving from this folded multiple-line representation
-    #  of a header field to its single line representation is called
-    #  "unfolding". Unfolding is accomplished by simply removing any CRLF
-    #  that is immediately followed by WSP.  Each header field should be
-    #  treated in its unfolded form for further syntactic and semantic
-    #  evaluation.
-    def unfold(string)
-      string.gsub(/#{CRLF}#{WSP}+/, ' ').gsub(/#{WSP}+/, ' ')
-    end
-    
-    # Returns the header with all the folds removed
-    def unfolded_header
-      @unfolded_header ||= unfold(raw_source)
-    end
-    
     # Splits an unfolded and line break cleaned header into individual field
     # strings.
     def split_header
-      self.fields = unfolded_header.split(CRLF)
+      self.fields = raw_source.split(HEADER_SPLIT)
     end
     
     def select_field_for(name)
```
