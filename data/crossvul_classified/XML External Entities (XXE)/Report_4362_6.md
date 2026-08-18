# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in ruby
**Pair ID:** 4362_6
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_6`)

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
      # Create a new Nokogiri::XML::Schema object using a +string_or_io+
      # object.
      def Schema string_or_io
        Schema.new(string_or_io)
      end
    end

    ###
    # Nokogiri::XML::Schema is used for validating XML against a schema
    # (usually from an xsd file).
    #
    # == Synopsis
    #
    # Validate an XML document against a Schema.  Loop over the errors that
    # are returned and print them out:
    #
    #   xsd = Nokogiri::XML::Schema(File.read(PO_SCHEMA_FILE))
    #   doc = Nokogiri::XML(File.read(PO_XML_FILE))
    #
    #   xsd.validate(doc).each do |error|
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
       # Create a new Nokogiri::XML::Schema object using a +string_or_io+
       # object.
-      def Schema string_or_io
-        Schema.new(string_or_io)
+      def Schema(string_or_io, options = ParseOptions::DEFAULT_SCHEMA)
+        Schema.new(string_or_io, options)
       end
     end
 
@@ -30,12 +30,14 @@
     class Schema
       # Errors while parsing the schema file
       attr_accessor :errors
+      # The Nokogiri::XML::ParseOptions used to parse the schema
+      attr_accessor :parse_options
 
       ###
       # Create a new Nokogiri::XML::Schema object using a +string_or_io+
       # object.
-      def self.new string_or_io
-        from_document Nokogiri::XML(string_or_io)
+      def self.new string_or_io, options = ParseOptions::DEFAULT_SCHEMA
+        from_document(Nokogiri::XML(string_or_io), options)
       end
 
       ###
```
