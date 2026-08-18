# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 4832_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4832_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 80-120 of the vulnerable file.

    # <tt>:file_start</tt>::    The +entry+ is a file; the extract of the
    #                           file is just beginning.
    # <tt>:file_progress</tt>:: Yielded every 4096 bytes during the extract
    #                           of the +entry+.
    # <tt>:file_done</tt>::     Yielded when the +entry+ is completed.
    #
    # The +stats+ hash contains the following keys:
    # <tt>:current</tt>:: The current total number of bytes read in the
    #                     +entry+.
    # <tt>:currinc</tt>:: The current number of bytes read in this read
    #                     cycle.
    # <tt>:entry</tt>::   The entry being extracted; this is a
    #                     Reader::EntryStream, with all methods thereof.
    def extract_entry(destdir, entry) # :yields action, name, stats:
      stats = {
        :current  => 0,
        :currinc  => 0,
        :entry    => entry
      }

      if entry.directory?
        dest = File.join(destdir, entry.full_name)

        yield :dir, entry.full_name, stats if block_given?

        if Archive::Tar::Minitar.dir?(dest)
          begin
            FileUtils.chmod(entry.mode, dest)
          rescue Exception
            nil
          end
        else
          FileUtils.mkdir_p(dest, :mode => entry.mode)
          FileUtils.chmod(entry.mode, dest)
        end

        fsync_dir(dest)
        fsync_dir(File.join(dest, ".."))
        return
      else # it's a file
        destdir = File.join(destdir, File.dirname(entry.full_name))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,10 +97,25 @@
         :entry    => entry
       }
 
+      # extract_entry is not vulnerable to prefix '/' vulnerabilities, but it
+      # is vulnerable to relative path directories. This code will break this
+      # vulnerability. For this version, we are breaking relative paths HARD by
+      # throwing an exception.
+      #
+      # Future versions may permit relative paths as long as the file does not
+      # leave +destdir+.
+      #
+      # However, squeeze consecutive '/' characters together.
+      full_name = entry.full_name.squeeze('/')
+
+      if full_name =~ /\.{2}(?:\/|\z)/
+        raise SecureRelativePathError, %q(Path contains '..')
+      end
+
       if entry.directory?
-        dest = File.join(destdir, entry.full_name)
+        dest = File.join(destdir, full_name)
 
-        yield :dir, entry.full_name, stats if block_given?
+        yield :dir, full_name, stats if block_given?
 
         if Archive::Tar::Minitar.dir?(dest)
           begin
@@ -109,6 +124,8 @@
             nil
           end
         else
+          File.unlink(dest.chomp('/')) if File.symlink?(dest.chomp('/'))
+
           FileUtils.mkdir_p(dest, :mode => entry.mode)
           FileUtils.chmod(entry.mode, dest)
         end
@@ -117,13 +134,16 @@
         fsync_dir(File.join(dest, ".."))
         return
       else # it's a file
-        destdir = File.join(destdir, File.dirname(entry.full_name))
+        destdir = File.join(destdir, File.dirname(full_name))
         FileUtils.mkdir_p(destdir, :mode => 0755)
 
-        destfile = File.join(destdir, File.basename(entry.full_name))
+        destfile = File.join(destdir, File.basename(full_name))
+
+        File.unlink(destfile) if File.symlink?(destfile)
+
         FileUtils.chmod(0600, destfile) rescue nil  # Errno::ENOENT
 
-        yield :file_start, entry.full_name, stats if block_given?
+        yield :file_start, full_name, stats if block_given?
 
         File.open(destfile, "wb", entry.mode) do |os|
           loop do
@@ -133,7 +153,7 @@
             stats[:currinc] = os.write(data)
             stats[:current] += stats[:currinc]
 
-            yield :file_progress, entry.full_name, stats if block_given?
+            yield :file_progress, full_name, stats if block_given?
           end
           os.fsync
         end
@@ -142,7 +162,7 @@
         fsync_dir(File.dirname(destfile))
         fsync_dir(File.join(File.dirname(destfile), ".."))
 
-        yield :file_done, entry.full_name, stats if block_given?
+        yield :file_done, full_name, stats if block_given?
       end
     end
 
```
