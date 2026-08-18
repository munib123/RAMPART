# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 379-419 of the vulnerable file.

  # in the history.  If +io_or_filename+ does not respond to #write it will be
  # used as a file name.  +parameters+, +referer+ and +headers+ are used as in
  # #get.
  #
  # By default, if the Content-type of the response matches a Mechanize::File
  # or Mechanize::Page parser, the response body will be loaded into memory
  # before being saved.  See #pluggable_parser for details on changing this
  # default.
  #
  # For alternate ways of downloading files see Mechanize::FileSaver and
  # Mechanize::DirectorySaver.

  def download uri, io_or_filename, parameters = [], referer = nil, headers = {}
    page = transact do
      get uri, parameters, referer, headers
    end

    io = if io_or_filename.respond_to? :write then
           io_or_filename
         else
           open io_or_filename, 'wb'
         end

    case page
    when Mechanize::File then
      io.write page.body
    else
      body_io = page.body_io

      until body_io.eof? do
        io.write body_io.read 16384
      end
    end

    page
  ensure
    io.close if io and not io_or_filename.respond_to? :write
  end

  ##
  # DELETE +uri+ with +query_params+, and setting +headers+:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -396,7 +396,7 @@
     io = if io_or_filename.respond_to? :write then
            io_or_filename
          else
-           open io_or_filename, 'wb'
+           ::File.open(io_or_filename, 'wb')
          end
 
     case page
```
