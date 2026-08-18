# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3727_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3727_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-26 of the vulnerable file.

require 'puppet'
require 'puppet/indirector'
require 'puppet/file_serving'
require 'puppet/file_serving/base'
require 'puppet/util/checksums'
require 'puppet/file_serving/indirection_hooks'

# A class that handles retrieving file metadata.
class Puppet::FileServing::Metadata < Puppet::FileServing::Base

  include Puppet::Util::Checksums

  extend Puppet::Indirector
  indirects :file_metadata, :extend => Puppet::FileServing::IndirectionHooks

  attr_reader :path, :owner, :group, :mode, :checksum_type, :checksum, :ftype, :destination

  PARAM_ORDER = [:mode, :ftype, :owner, :group]

  def attributes_with_tabs
    raise(ArgumentError, "Cannot manage files of type #{ftype}") unless ['file','directory','link'].include? ftype
    desc = []
    PARAM_ORDER.each { |check|
      check = :ftype if check == :type
      desc << send(check)
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,6 @@
 require 'puppet/file_serving'
 require 'puppet/file_serving/base'
 require 'puppet/util/checksums'
-require 'puppet/file_serving/indirection_hooks'
 
 # A class that handles retrieving file metadata.
 class Puppet::FileServing::Metadata < Puppet::FileServing::Base
@@ -11,7 +10,7 @@
   include Puppet::Util::Checksums
 
   extend Puppet::Indirector
-  indirects :file_metadata, :extend => Puppet::FileServing::IndirectionHooks
+  indirects :file_metadata, :terminus_class => :selector
 
   attr_reader :path, :owner, :group, :mode, :checksum_type, :checksum, :ftype, :destination
 
```
