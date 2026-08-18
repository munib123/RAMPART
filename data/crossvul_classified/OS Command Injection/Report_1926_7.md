# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_7
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

require 'stringio'
require 'zlib'

class GzipServlet < WEBrick::HTTPServlet::AbstractServlet

  TEST_DIR = File.expand_path '../../../../test', __FILE__

  def do_GET(req, res)
    if req['Accept-Encoding'] !~ /gzip/ then
      res.code = 400
      res.body = 'Content-Encoding: gzip is not supported by your user-agent'
      return
    end

    if name = req.query['file'] then
      open "#{TEST_DIR}/htdocs/#{name}" do |io|
        string = String.new
        zipped = StringIO.new string, 'w'
        Zlib::GzipWriter.wrap zipped do |gz|
          gz.write io.read
        end
        res.body = string
      end
    else
      res.body = String.new
    end

    res['Content-Encoding'] = req['X-ResponseContentEncoding'] || 'gzip'
    res['Content-Type'] = "text/html"
  end
end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
     end
 
     if name = req.query['file'] then
-      open "#{TEST_DIR}/htdocs/#{name}" do |io|
+      ::File.open("#{TEST_DIR}/htdocs/#{name}") do |io|
         string = String.new
         zipped = StringIO.new string, 'w'
         Zlib::GzipWriter.wrap zipped do |gz|
```
