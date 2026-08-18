# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 65-93 of the vulnerable file.

    save! filename
  end

  alias save_as save

  ##
  # Use this method to save the content of this object to +filename+.
  # This method will overwrite any existing filename that exists with the
  # same name.
  # returns the filename
  #
  #   file.save 'index.html'
  #   file.save! 'index.html' # overwrite original file
  #   filename = file.save! 'index.html' # overwrite original file with filename 'index.html'

  def save! filename = nil
    filename ||= @filename
    dirname = File.dirname filename
    FileUtils.mkdir_p dirname

    open filename, 'wb' do |f|
      f.write body
    end

    filename
  end

end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,7 @@
     dirname = File.dirname filename
     FileUtils.mkdir_p dirname
 
-    open filename, 'wb' do |f|
+    ::File.open(filename, 'wb')do |f|
       f.write body
     end
 
```
