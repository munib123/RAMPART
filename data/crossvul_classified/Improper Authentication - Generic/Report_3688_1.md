# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 3688_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3688_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 27-69 of the vulnerable file.


  before(:each) do
    Puppet[:rest_authconfig] = tmpfile('auth.conf')
  end

  def add_rule(rule)
    File.open(Puppet[:rest_authconfig],"w+") do |f|
      f.print "path /test\n#{rule}\n"
    end
    @auth = Puppet::Network::RestAuthConfig.new(Puppet[:rest_authconfig], true)
  end

  def add_regex_rule(regex, rule)
    File.open(Puppet[:rest_authconfig],"w+") do |f|
      f.print "path ~ #{regex}\n#{rule}\n"
    end
    @auth = Puppet::Network::RestAuthConfig.new(Puppet[:rest_authconfig], true)
  end

  def request(args = {})
    { :ip => '10.1.1.1', :node => 'host.domain.com', :key => 'key', :authenticated => true }.each do |k,v|
      args[k] ||= v
    end
    ['test', :find, args[:key], args]
  end

  it "should support IPv4 address" do
    add_rule("allow 10.1.1.1")

    @auth.should allow(request)
  end

  it "should support CIDR IPv4 address" do
    add_rule("allow 10.0.0.0/8")

    @auth.should allow(request)
  end

  it "should support wildcard IPv4 address" do
    add_rule("allow 10.1.1.*")

    @auth.should allow(request)
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,10 +44,29 @@
   end
 
   def request(args = {})
-    { :ip => '10.1.1.1', :node => 'host.domain.com', :key => 'key', :authenticated => true }.each do |k,v|
-      args[k] ||= v
-    end
+    args = {
+      :key => 'key',
+      :node => 'host.domain.com',
+      :ip => '10.1.1.1',
+      :authenticated => true
+    }.merge(args)
     ['test', :find, args[:key], args]
+  end
+
+  it "should warn when matching against IP addresses" do
+    add_rule("allow 10.1.1.1")
+
+    @auth.should allow(request)
+
+    @logs.should be_any {|log| log.level == :warning and log.message =~ /Authentication based on IP address is deprecated/}
+  end
+
+  it "should not warn when matches against IP addresses fail" do
+    add_rule("allow 10.1.1.2")
+
+    @auth.should_not allow(request)
+
+    @logs.should_not be_any {|log| log.level == :warning and log.message =~ /Authentication based on IP address is deprecated/}
   end
 
   it "should support IPv4 address" do
```
