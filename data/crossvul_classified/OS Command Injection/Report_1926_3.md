# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 54-84 of the vulnerable file.

  # returns the filename

  def save filename = nil
    filename = find_free_name filename
    save! filename
  end

  alias save_as save

  ##
  # Use this method to save the content of body_io to +filename+.
  # This method will overwrite any existing filename that exists with the
  # same name.
  # returns the filename

  def save! filename = nil
    filename ||= @filename
    dirname = File.dirname filename
    FileUtils.mkdir_p dirname

    open filename, 'wb' do |io|
      until @body_io.eof? do
        io.write @body_io.read 16384
      end
    end

    filename
  end

end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
     dirname = File.dirname filename
     FileUtils.mkdir_p dirname
 
-    open filename, 'wb' do |io|
+    ::File.open(filename, 'wb')do |io|
       until @body_io.eof? do
         io.write @body_io.read 16384
       end
```
