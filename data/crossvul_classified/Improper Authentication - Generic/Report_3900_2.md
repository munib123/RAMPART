# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 3900_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3900_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 23-63 of the vulnerable file.

          callback.call(message)
        end
      end
      server.add_extension(extension.new)
    end

    it "passes incoming messages through the extension" do
      engine.should_receive(:publish).with({"channel" => "/foo", "data" => "hello", "ext" => {"auth" => "password"}})
      server.process(message, false) {}
    end

    it "does not pass outgoing messages through the extension" do
      server.stub(:handshake).and_yield(message)
      engine.stub(:publish)
      response = nil
      server.process({"channel" => "/meta/handshake"}, false) { |r| response = r }
      response.should == [{"channel" => "/foo", "data" => "hello"}]
    end
  end

  describe "with an outgoing extension installed" do
    before do
      extension = Class.new do
        def outgoing(message, callback)
          message["ext"] = {"auth" => "password"}
          callback.call(message)
        end
      end
      server.add_extension(extension.new)
    end

    it "does not pass incoming messages through the extension" do
      engine.should_receive(:publish).with({"channel" => "/foo", "data" => "hello"})
      server.process(message, false) {}
    end

    it "passes outgoing messages through the extension" do
      server.stub(:handshake).and_yield(message)
      engine.stub(:publish)
      response = nil
      server.process({"channel" => "/meta/handshake"}, false) { |r| response = r }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,42 @@
     end
   end
 
+  describe "with subscription auth installed" do
+    before do
+      extension = Class.new do
+        def incoming(message, callback)
+          if message["channel"] == "/meta/subscribe" and !message["auth"]
+            message["error"] = "Invalid auth"
+          end
+          callback.call(message)
+        end
+      end
+      server.add_extension(extension.new)
+    end
+
+    it "does not subscribe using the intended channel" do
+      message = {
+        "channel" => "/meta/subscribe",
+        "clientId" => "fakeclientid",
+        "subscription" => "/foo"
+      }
+      engine.stub(:client_exists).and_yield(true)
+      engine.should_not_receive(:subscribe)
+      server.process(message, false) {}
+    end
+
+    it "does not subscribe using an extended channel" do
+      message = {
+        "channel" => "/meta/subscribe/x",
+        "clientId" => "fakeclientid",
+        "subscription" => "/foo"
+      }
+      engine.stub(:client_exists).and_yield(true)
+      engine.should_not_receive(:subscribe)
+      server.process(message, false) {}
+    end
+  end
+
   describe "with an outgoing extension installed" do
     before do
       extension = Class.new do
```
