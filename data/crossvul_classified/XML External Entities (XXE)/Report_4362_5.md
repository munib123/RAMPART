# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in ruby
**Pair ID:** 4362_5
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

# frozen_string_literal: true
module Nokogiri
  module XML
    class << self
      ###
      # Create a new Nokogiri::XML::RelaxNG document from +string_or_io+.
      # See Nokogiri::XML::RelaxNG for an example.
      def RelaxNG string_or_io
        RelaxNG.new(string_or_io)
      end
    end

    ###
    # Nokogiri::XML::RelaxNG is used for validating XML against a
    # RelaxNG schema.
    #
    # == Synopsis
    #
    # Validate an XML document against a RelaxNG schema.  Loop over the errors
    # that are returned and print them out:
    #
    #   schema  = Nokogiri::XML::RelaxNG(File.open(ADDRESS_SCHEMA_FILE))
    #   doc     = Nokogiri::XML(File.open(ADDRESS_XML_FILE))
    #
    #   schema.validate(doc).each do |error|
    #     puts error.message
    #   end
    #
    # The list of errors are Nokogiri::XML::SyntaxError objects.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,8 +5,8 @@
       ###
       # Create a new Nokogiri::XML::RelaxNG document from +string_or_io+.
       # See Nokogiri::XML::RelaxNG for an example.
-      def RelaxNG string_or_io
-        RelaxNG.new(string_or_io)
+      def RelaxNG(string_or_io, options = ParseOptions::DEFAULT_SCHEMA)
+        RelaxNG.new(string_or_io, options)
       end
     end
 
```
