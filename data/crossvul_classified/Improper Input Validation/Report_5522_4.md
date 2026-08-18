# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 5522_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5522_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 23-63 of the vulnerable file.

  it "should process when parsing complete" do
    @connection.request.should_receive(:parse).and_return(true)
    @connection.should_receive(:process)
    @connection.receive_data('GET')
  end
  
  it "should process" do
    @connection.process
  end
  
  it "should rescue error in process" do
    @connection.app.should_receive(:call).and_raise(StandardError)
    @connection.process
  end
  
  it "should rescue Timeout error in process" do
    @connection.app.should_receive(:call).and_raise(Timeout::Error.new("timeout error not rescued"))
    @connection.process
  end
  
  it "should return HTTP_X_FORWARDED_FOR as remote_address" do
    @connection.request.env['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
    @connection.remote_address.should == '1.2.3.4'
  end
  
  it "should return nil on error retreiving remote_address" do
    @connection.stub!(:get_peername).and_raise(RuntimeError)
    @connection.remote_address.should be_nil
  end
  
  it "should return nil on nil get_peername" do
    @connection.stub!(:get_peername).and_return(nil)
    @connection.remote_address.should be_nil
  end
  
  it "should return nil on empty get_peername" do
    @connection.stub!(:get_peername).and_return('')
    @connection.remote_address.should be_nil
  end
  
  it "should return remote_address" do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,9 +40,10 @@
     @connection.process
   end
   
-  it "should return HTTP_X_FORWARDED_FOR as remote_address" do
+  it "should not return HTTP_X_FORWARDED_FOR as remote_address" do
     @connection.request.env['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
-    @connection.remote_address.should == '1.2.3.4'
+    @connection.stub!(:socket_address).and_return("127.0.0.1")
+    @connection.remote_address.should == "127.0.0.1"
   end
   
   it "should return nil on error retreiving remote_address" do
```
