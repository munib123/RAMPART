# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in ruby
**Pair ID:** 1925_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1925_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```ruby
Lines 1-8 of the vulnerable file.

When /^I download the file '([^']+)'/ do |url|
  unless ENV['REMOTE'] == 'true'
    stub_request(:get, "s3.amazonaws.com/Monkey/testfile.txt").
      to_return(body: "S3 Remote File", headers: { "Content-Type" => "text/plain" })
  end

  @uploader.download!(url)
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 When /^I download the file '([^']+)'/ do |url|
   unless ENV['REMOTE'] == 'true'
-    stub_request(:get, "s3.amazonaws.com/Monkey/testfile.txt").
+    stub_request(:get, %r{/Monkey/testfile.txt}).
       to_return(body: "S3 Remote File", headers: { "Content-Type" => "text/plain" })
   end
 
```
