# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_5
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 1-38 of the vulnerable file.

##
# Fake response for dealing with file:/// requests

class Mechanize::FileResponse

  def initialize(file_path)
    @file_path = file_path
    @uri       = nil
  end

  def read_body
    raise Mechanize::ResponseCodeError.new(self) unless
      File.exist? @file_path

    if directory?
      yield dir_body
    else
      open @file_path, 'rb' do |io|
        yield io.read
      end
    end
  end

  def code
    File.exist?(@file_path) ? 200 : 404
  end

  def content_length
    return dir_body.length if directory?
    File.exist?(@file_path) ? File.stat(@file_path).size : 0
  end

  def each_header; end

  def [](key)
    return nil if key.casecmp('Content-Type') != 0
    return 'text/html' if directory?
    return 'text/html' if ['.html', '.xhtml'].any? { |extn|
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,7 @@
     if directory?
       yield dir_body
     else
-      open @file_path, 'rb' do |io|
+      ::File.open(@file_path, 'rb') do |io|
         yield io.read
       end
     end
```
