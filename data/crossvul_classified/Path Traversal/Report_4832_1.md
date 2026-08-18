# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 4832_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4832_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 56-96 of the vulnerable file.

#
# As the case above shows, one need not write to a file. However, it will
# sometimes require that one dive a little deeper into the API, as in the case
# of StringIO objects. Note that I'm not providing a block with
# Minitar::Output, as Minitar::Output#close automatically closes both the
# Output object and the wrapped data stream object.
#
#     begin
#       sgz = Zlib::GzipWriter.new(StringIO.new(""))
#       tar = Output.new(sgz)
#       Find.find('tests') do |entry|
#         Minitar.pack_file(entry, tar)
#       end
#     ensure
#         # Closes both tar and sgz.
#       tar.close
#     end
module Archive::Tar::Minitar
  VERSION = '0.6' # :nodoc:

  # Raised when a wrapped data stream class is not seekable.
  NonSeekableStream = Class.new(StandardError)
  # The exception raised when operations are performed on a stream that has
  # previously been closed.
  ClosedStream = Class.new(StandardError)
  # The exception raised when a filename exceeds 256 bytes in length, the
  # maximum supported by the standard Tar format.
  FileNameTooLong = Class.new(StandardError)
  # The exception raised when a data stream ends before the amount of data
  # expected in the archive's PosixHeader.
  UnexpectedEOF = Class.new(StandardError)

  class << self
    # Tests if +path+ refers to a directory. Fixes an apparently
    # corrupted <tt>stat()</tt> call on Windows.
    def dir?(path)
      File.directory?((path[-1] == ?/) ? path : "#{path}/")
    end

    # A convenience method for wrapping Archive::Tar::Minitar::Input.open
    # (mode +r+) and Archive::Tar::Minitar::Output.open (mode +w+). No other
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,17 +73,22 @@
 module Archive::Tar::Minitar
   VERSION = '0.6' # :nodoc:
 
+  # The base class for any minitar error.
+  Error = Class.new(StandardError)
   # Raised when a wrapped data stream class is not seekable.
-  NonSeekableStream = Class.new(StandardError)
+  NonSeekableStream = Class.new(Error)
   # The exception raised when operations are performed on a stream that has
   # previously been closed.
-  ClosedStream = Class.new(StandardError)
+  ClosedStream = Class.new(Error)
   # The exception raised when a filename exceeds 256 bytes in length, the
   # maximum supported by the standard Tar format.
-  FileNameTooLong = Class.new(StandardError)
+  FileNameTooLong = Class.new(Error)
   # The exception raised when a data stream ends before the amount of data
   # expected in the archive's PosixHeader.
   UnexpectedEOF = Class.new(StandardError)
+  # The exception raised when a file contains a relative path in secure mode
+  # (the default for this version).
+  SecureRelativePathError = Class.new(Error)
 
   class << self
     # Tests if +path+ refers to a directory. Fixes an apparently
```
