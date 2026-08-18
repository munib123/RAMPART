# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3728_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3728_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-34 of the vulnerable file.

#!/usr/bin/env ruby
#
#  Created by Luke Kanies on 2007-10-18.
#  Copyright (c) 2007. All rights reserved.

shared_examples_for "Puppet::FileServing::Files" do
  it "should use the rest terminus when the 'puppet' URI scheme is used and a host name is present" do
    uri = "puppet://myhost/fakemod/my/file"

    # It appears that the mocking somehow interferes with the caching subsystem.
    # This mock somehow causes another terminus to get generated.
    term = @indirection.terminus(:rest)
    @indirection.stubs(:terminus).with(:rest).returns term
    term.expects(:find)
    @test_class.find(uri)
  end

  it "should use the rest terminus when the 'puppet' URI scheme is used, no host name is present, and the process name is not 'puppet' or 'apply'" do
    uri = "puppet:///fakemod/my/file"
    Puppet.settings.stubs(:value).returns "foo"
    Puppet.settings.stubs(:value).with(:name).returns("puppetd")
    Puppet.settings.stubs(:value).with(:modulepath).returns("")
    @indirection.terminus(:rest).expects(:find)
    @test_class.find(uri)
  end

  it "should use the file_server terminus when the 'puppet' URI scheme is used, no host name is present, and the process name is 'puppet'" do
    uri = "puppet:///fakemod/my/file"
    Puppet::Node::Environment.stubs(:new).returns(stub("env", :name => "testing", :module => nil, :modulepath => []))
    Puppet.settings.stubs(:value).returns ""
    Puppet.settings.stubs(:value).with(:name).returns("puppet")
    Puppet.settings.stubs(:value).with(:fileserverconfig).returns("/whatever")
    @indirection.terminus(:file_server).expects(:find)
    @indirection.terminus(:file_server).stubs(:authorized?).returns(true)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,9 +9,7 @@
 
     # It appears that the mocking somehow interferes with the caching subsystem.
     # This mock somehow causes another terminus to get generated.
-    term = @indirection.terminus(:rest)
-    @indirection.stubs(:terminus).with(:rest).returns term
-    term.expects(:find)
+    @indirection.terminus(:rest).expects(:find)
     @test_class.find(uri)
   end
 
```
