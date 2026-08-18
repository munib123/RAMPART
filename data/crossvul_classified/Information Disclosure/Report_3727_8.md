# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3727_8
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3727_8`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

#!/usr/bin/env rspec
require 'spec_helper'

require 'puppet/file_serving/content'

describe Puppet::FileServing::Content do
  let(:path) { File.expand_path('/path') }

  it "should should be a subclass of Base" do
    Puppet::FileServing::Content.superclass.should equal(Puppet::FileServing::Base)
  end

  it "should indirect file_content" do
    Puppet::FileServing::Content.indirection.name.should == :file_content
  end

  it "should should include the IndirectionHooks module in its indirection" do
    Puppet::FileServing::Content.indirection.singleton_class.included_modules.should include(Puppet::FileServing::IndirectionHooks)
  end

  it "should only support the raw format" do
    Puppet::FileServing::Content.supported_formats.should == [:raw]
  end

  it "should have a method for collecting its attributes" do
    Puppet::FileServing::Content.new(path).should respond_to(:collect)
  end

  it "should not retrieve and store its contents when its attributes are collected if the file is a normal file" do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,16 +6,12 @@
 describe Puppet::FileServing::Content do
   let(:path) { File.expand_path('/path') }
 
-  it "should should be a subclass of Base" do
+  it "should be a subclass of Base" do
     Puppet::FileServing::Content.superclass.should equal(Puppet::FileServing::Base)
   end
 
   it "should indirect file_content" do
     Puppet::FileServing::Content.indirection.name.should == :file_content
-  end
-
-  it "should should include the IndirectionHooks module in its indirection" do
-    Puppet::FileServing::Content.indirection.singleton_class.included_modules.should include(Puppet::FileServing::IndirectionHooks)
   end
 
   it "should only support the raw format" do
```
