# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1116_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1116_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 15-41 of the vulnerable file.

    content_type :json
    request.env.select{|key, _| key.start_with? 'HTTP_'}.to_json
  end

  post('/body-sink') do
    request.body.read.size.to_s
  end

  post('/echo') do
    echo
  end

  put('/echo') do
    echo
  end

  get('/echo dirty') do
    echo
  end

  private

  def echo
    request.body.read
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,14 @@
     echo
   end
 
+  get('/foo') do
+    'foo'
+  end
+
+  get('/bar') do
+    'bar'
+  end
+
   private
 
   def echo
```
