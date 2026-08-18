# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3728_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3728_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-28 of the vulnerable file.

#
#  Created by Luke Kanies on 2007-10-16.
#  Copyright (c) 2007. All rights reserved.

require 'puppet/indirector'
require 'puppet/file_serving'
require 'puppet/file_serving/base'
require 'puppet/file_serving/indirection_hooks'

# A class that handles retrieving file contents.
# It only reads the file when its content is specifically
# asked for.
class Puppet::FileServing::Content < Puppet::FileServing::Base
  extend Puppet::Indirector
  indirects :file_content, :extend => Puppet::FileServing::IndirectionHooks

  attr_writer :content

  def self.supported_formats
    [:raw]
  end

  def self.from_raw(content)
    instance = new("/this/is/a/fake/path")
    instance.content = content
    instance
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,14 +5,13 @@
 require 'puppet/indirector'
 require 'puppet/file_serving'
 require 'puppet/file_serving/base'
-require 'puppet/file_serving/indirection_hooks'
 
 # A class that handles retrieving file contents.
 # It only reads the file when its content is specifically
 # asked for.
 class Puppet::FileServing::Content < Puppet::FileServing::Base
   extend Puppet::Indirector
-  indirects :file_content, :extend => Puppet::FileServing::IndirectionHooks
+  indirects :file_content, :terminus_class => :selector
 
   attr_writer :content
 
```
