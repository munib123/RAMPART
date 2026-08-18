# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in ruby
**Pair ID:** 4362_4
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```ruby
Lines 56-96 of the vulnerable file.

      NODICT      = 1 << 12
      # remove redundant namespaces declarations
      NSCLEAN     = 1 << 13
      # merge CDATA as text nodes
      NOCDATA     = 1 << 14
      # do not generate XINCLUDE START/END nodes
      NOXINCNODE  = 1 << 15
      # compact small text nodes; no modification of the tree allowed afterwards (will possibly crash if you try to modify the tree)
      COMPACT     = 1 << 16
      # parse using XML-1.0 before update 5
      OLD10       = 1 << 17
      # do not fixup XINCLUDE xml:base uris
      NOBASEFIX   = 1 << 18
      # relax any hardcoded limit from the parser
      HUGE        = 1 << 19

      # the default options used for parsing XML documents
      DEFAULT_XML  = RECOVER | NONET
      # the default options used for parsing HTML documents
      DEFAULT_HTML = RECOVER | NOERROR | NOWARNING | NONET

      attr_accessor :options
      def initialize options = STRICT
        @options = options
      end

      constants.each do |constant|
        next if constant.to_sym == :STRICT
        class_eval %{
          def #{constant.downcase}
            @options |= #{constant}
            self
          end

          def no#{constant.downcase}
            @options &= ~#{constant}
            self
          end

          def #{constant.downcase}?
            #{constant} & @options == #{constant}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,8 @@
       DEFAULT_XML  = RECOVER | NONET
       # the default options used for parsing HTML documents
       DEFAULT_HTML = RECOVER | NOERROR | NOWARNING | NONET
+      # the default options used for parsing XML schemas
+      DEFAULT_SCHEMA = NONET
 
       attr_accessor :options
       def initialize options = STRICT
```
