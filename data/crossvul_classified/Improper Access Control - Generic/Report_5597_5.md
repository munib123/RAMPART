# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5597_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5597_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 367-411 of the vulnerable file.

        o[:connection_adapter_options].should == connection_adapter_options
        HTTParty::ConnectionAdapter.call(u,o)
      end.with(URI.parse(uri), kind_of(Hash))
      FakeWeb.register_uri(:get, uri, :body => 'stuff')
      @klass.connection_adapter connection_adapter, connection_adapter_options
      @klass.get(uri).should == 'stuff'
    end
  end

  describe "format" do
    it "should allow xml" do
      @klass.format :xml
      @klass.default_options[:format].should == :xml
    end

    it "should allow json" do
      @klass.format :json
      @klass.default_options[:format].should == :json
    end

    it "should allow yaml" do
      @klass.format :yaml
      @klass.default_options[:format].should == :yaml
    end

    it "should allow plain" do
      @klass.format :plain
      @klass.default_options[:format].should == :plain
    end

    it 'should not allow funky format' do
      lambda do
        @klass.format :foobar
      end.should raise_error(HTTParty::UnsupportedFormat)
    end

    it 'should only print each format once with an exception' do
      lambda do
        @klass.format :foobar
      end.should raise_error(HTTParty::UnsupportedFormat, "':foobar' Must be one of: html, json, plain, xml, yaml")
    end

    it 'sets the default parser' do
      @klass.default_options[:parser].should be_nil
      @klass.format :json
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -384,11 +384,6 @@
       @klass.default_options[:format].should == :json
     end
 
-    it "should allow yaml" do
-      @klass.format :yaml
-      @klass.default_options[:format].should == :yaml
-    end
-
     it "should allow plain" do
       @klass.format :plain
       @klass.default_options[:format].should == :plain
@@ -403,7 +398,7 @@
     it 'should only print each format once with an exception' do
       lambda do
         @klass.format :foobar
-      end.should raise_error(HTTParty::UnsupportedFormat, "':foobar' Must be one of: html, json, plain, xml, yaml")
+      end.should raise_error(HTTParty::UnsupportedFormat, "':foobar' Must be one of: html, json, plain, xml")
     end
 
     it 'sets the default parser' do
```
