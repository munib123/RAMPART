# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3728_9
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3728_9`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-37 of the vulnerable file.

#!/usr/bin/env ruby

require File.dirname(__FILE__) + '/../../spec_helper'

require 'puppet/file_serving/metadata'

describe Puppet::FileServing::Metadata do
  it "should should be a subclass of Base" do
    Puppet::FileServing::Metadata.superclass.should equal(Puppet::FileServing::Base)
  end

  it "should indirect file_metadata" do
    Puppet::FileServing::Metadata.indirection.name.should == :file_metadata
  end

  it "should should include the IndirectionHooks module in its indirection" do
    Puppet::FileServing::Metadata.indirection.singleton_class.included_modules.should include(Puppet::FileServing::IndirectionHooks)
  end

  it "should have a method that triggers attribute collection" do
    Puppet::FileServing::Metadata.new("/foo/bar").should respond_to(:collect)
  end

  it "should support pson serialization" do
    Puppet::FileServing::Metadata.new("/foo/bar").should respond_to(:to_pson)
  end

  it "should support to_pson_data_hash" do
    Puppet::FileServing::Metadata.new("/foo/bar").should respond_to(:to_pson_data_hash)
  end

  it "should support pson deserialization" do
    Puppet::FileServing::Metadata.should respond_to(:from_pson)
  end

  describe "when serializing" do
    before do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,10 +11,6 @@
 
   it "should indirect file_metadata" do
     Puppet::FileServing::Metadata.indirection.name.should == :file_metadata
-  end
-
-  it "should should include the IndirectionHooks module in its indirection" do
-    Puppet::FileServing::Metadata.indirection.singleton_class.included_modules.should include(Puppet::FileServing::IndirectionHooks)
   end
 
   it "should have a method that triggers attribute collection" do
```
