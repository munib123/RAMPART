# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 74-114 of the vulnerable file.


      Puppet::Node.indirection.expects(:find).with("my_node", anything).returns @node
      @compiler.expects(:compile).with(@node, anything)
      @compiler.find(@request)
    end

    it "should fail if no node is passed and none can be found" do
      Puppet::Node.indirection.stubs(:find).with(@name, anything).returns(nil)
      expect { @compiler.find(@request) }.to raise_error(ArgumentError)
    end

    it "should fail intelligently when searching for a node raises an exception" do
      Puppet::Node.indirection.stubs(:find).with(@name, anything).raises "eh"
      expect { @compiler.find(@request) }.to raise_error(Puppet::Error)
    end

    it "should pass the found node to the compiler for compiling" do
      Puppet::Node.indirection.expects(:find).with(@name, anything).returns(@node)
      config = mock 'config'
      Puppet::Parser::Compiler.expects(:compile).with(@node, anything)
      @compiler.find(@request)
    end

    it "should extract and save any facts from the request" do
      Puppet::Node.indirection.expects(:find).with(@name, anything).returns @node
      @compiler.expects(:extract_facts_from_request).with(@request)
      Puppet::Parser::Compiler.stubs(:compile)
      @compiler.find(@request)
    end

    it "requires `facts_format` option if facts are passed in" do
      facts = Puppet::Node::Facts.new("mynode", :afact => "avalue")
      request = Puppet::Indirector::Request.new(:catalog, :find, "mynode", nil, :facts => facts)
      expect {
        @compiler.find(request)
      }.to raise_error ArgumentError, /no fact format provided for mynode/
    end

    it "rejects facts in the request from a different node" do
      facts = Puppet::Node::Facts.new("differentnode", :afact => "avalue")
      request = Puppet::Indirector::Request.new(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,13 @@
       Puppet::Node.indirection.expects(:find).with(@name, anything).returns(@node)
       config = mock 'config'
       Puppet::Parser::Compiler.expects(:compile).with(@node, anything)
+      @compiler.find(@request)
+    end
+
+    it "should pass node containing percent character to the compiler" do
+      node_with_percent_character = Puppet::Node.new "%6de"
+      Puppet::Node.indirection.stubs(:find).returns(node_with_percent_character)
+      Puppet::Parser::Compiler.expects(:compile).with(node_with_percent_character, anything)
       @compiler.find(@request)
     end
 
```
