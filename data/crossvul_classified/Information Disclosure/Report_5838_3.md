# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5838_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5838_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe UsersController do
  describe "routing" do

    it "recognizes and generates #index" do
      { :get => "/users" }.should route_to(:controller => "users", :action => "index")
    end

    it "recognizes and generates #new as /signup" do
      { :get => "/signup" }.should route_to(:controller => "users", :action => "new")
    end

    it "recognizes and generates #show as /profile" do
      { :get => "/profile" }.should route_to(:controller => "users", :action => "show")
    end

    it "recognizes and generates #edit" do
      { :get => "/users/1/edit" }.should route_to(:controller => "users", :action => "edit", :id => "1")
    end

    it "doesn't recognize #edit with non-numeric id" do
      { :get => "/opportunities/aaron/edit" }.should_not be_routable
    end

    it "recognizes and generates #create" do
      { :post => "/users" }.should route_to(:controller => "users", :action => "create")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,8 +8,8 @@
 describe UsersController do
   describe "routing" do
 
-    it "recognizes and generates #index" do
-      { :get => "/users" }.should route_to(:controller => "users", :action => "index")
+    it "doesn't recognize #index" do
+      { :get => "/users" }.should_not be_routable
     end
 
     it "recognizes and generates #new as /signup" do
@@ -40,8 +40,8 @@
       { :put => "/opportunities/aaron" }.should_not be_routable
     end
 
-    it "recognizes and generates #destroy" do
-      { :delete => "/users/1" }.should route_to(:controller => "users", :action => "destroy", :id => "1")
+    it "doesn't recognize #destroy" do
+      { :delete => "/users/1" }.should_not be_routable
     end
 
     it "doesn't recognize #destroy with non-numeric id" do
@@ -81,4 +81,3 @@
     end
   end
 end
-
```
