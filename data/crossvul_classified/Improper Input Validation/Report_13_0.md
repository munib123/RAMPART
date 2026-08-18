# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 13_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `13_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-38 of the vulnerable file.

# -*- coding: utf-8 -*-
# frozen_string_literal: true
#--
# Copyright 2006 by Chad Fowler, Rich Kilmer, Jim Weirich and others.
# All rights reserved.
# See LICENSE.txt for permissions.
#++


require 'rubygems/version'
require 'rubygems/requirement'
require 'rubygems/platform'
require 'rubygems/deprecate'
require 'rubygems/basic_specification'
require 'rubygems/stub_specification'
require 'rubygems/util/list'
require 'stringio'

##
# The Specification class contains the information for a Gem.  Typically
# defined in a .gemspec file or a Rakefile, and looks like this:
#
#   Gem::Specification.new do |s|
#     s.name        = 'example'
#     s.version     = '0.1.0'
#     s.licenses    = ['MIT']
#     s.summary     = "This is an example!"
#     s.description = "Much longer explanation of the example!"
#     s.authors     = ["Ruby Coder"]
#     s.email       = 'rubycoder@example.com'
#     s.files       = ["lib/example.rb"]
#     s.homepage    = 'https://rubygems.org/gems/example'
#     s.metadata    = { "source_code_uri" => "https://github.com/example/example" }
#   end
#
# Starting in RubyGems 2.0, a Specification can hold arbitrary
# metadata.  See #metadata for restrictions on the format and size of metadata
# items you may add to a specification.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 require 'rubygems/stub_specification'
 require 'rubygems/util/list'
 require 'stringio'
+require 'uri'
 
 ##
 # The Specification class contains the information for a Gem.  Typically
@@ -2822,10 +2823,16 @@
       raise Gem::InvalidSpecificationException, "#{lazy} is not a summary"
     end
 
-    if homepage and not homepage.empty? and
-       homepage !~ /\A[a-z][a-z\d+.-]*:/i then
-      raise Gem::InvalidSpecificationException,
-            "\"#{homepage}\" is not a URI"
+    # Make sure a homepage is valid HTTP/HTTPS URI
+    if homepage and not homepage.empty?
+      begin
+        homepage_uri = URI.parse(homepage)
+        unless [URI::HTTP, URI::HTTPS].member? homepage_uri.class
+          raise Gem::InvalidSpecificationException, "\"#{homepage}\" is not a URI"
+        end
+      rescue URI::InvalidURIError
+        raise Gem::InvalidSpecificationException, "\"#{homepage}\" is not a URI"
+      end
     end
 
     # Warnings
```
