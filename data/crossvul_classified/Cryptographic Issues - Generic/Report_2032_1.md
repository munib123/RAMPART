# CrossVul Fix Pair: Cryptographic Issues in ruby
**Pair ID:** 2032_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2032_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```ruby
Lines 539-577 of the vulnerable file.

      def which(cmd)
        exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
        ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
          exts.each { |ext|
            exe = "#{path}/#{cmd}#{ext}"
            return exe if File.executable? exe
          }
        end
        return nil
      end

      # Checks whether a command exists on this system in the $PATH.
      #
      # name - The String name of the command to check for.
      #
      # Returns a Boolean.
      def command?(name)
        !which(name).nil?
      end

      def tmp_dir
        ENV['TMPDIR'] || ENV['TEMP'] || '/tmp'
      end

      def terminal_width
        if unix?
          width = %x{stty size 2>#{NULL}}.split[1].to_i
          width = %x{tput cols 2>#{NULL}}.to_i if width.zero?
        else
          width = 0
        end
        width < 10 ? 78 : width
      end
    end

    include System
    extend System
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -556,10 +556,6 @@
         !which(name).nil?
       end
 
-      def tmp_dir
-        ENV['TMPDIR'] || ENV['TEMP'] || '/tmp'
-      end
-
       def terminal_width
         if unix?
           width = %x{stty size 2>#{NULL}}.split[1].to_i
```
