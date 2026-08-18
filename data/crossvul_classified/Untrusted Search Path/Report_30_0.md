# CrossVul Fix Pair: Untrusted Search Path in ruby
**Pair ID:** 30_0
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `30_0`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```ruby
Lines 108-148 of the vulnerable file.


          libnames.each do |libname|
            begin
              orig = libname
              lib = FFI::DynamicLibrary.open(libname, lib_flags)
              break if lib

            rescue Exception => ex
              ldscript = false
              if ex.message =~ /(([^ \t()])+\.so([^ \t:()])*):([ \t])*(invalid ELF header|file too short|invalid file format)/
                if File.read($1) =~ /(?:GROUP|INPUT) *\( *([^ \)]+)/
                  libname = $1
                  ldscript = true
                end
              end

              if ldscript
                retry
              else
                # TODO better library lookup logic
                unless libname.start_with?("/")
                  path = ['/usr/lib/','/usr/local/lib/'].find do |pth|
                    File.exist?(pth + libname)
                  end
                  if path
                    libname = path + libname
                    retry
                  end
                end

                libr = (orig == libname ? orig : "#{orig} #{libname}")
                errors[libr] = ex
              end
            end
          end

          if lib.nil?
            raise LoadError.new(errors.values.join(".\n"))
          end

          # return the found lib
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,7 +125,7 @@
                 retry
               else
                 # TODO better library lookup logic
-                unless libname.start_with?("/")
+                unless libname.start_with?("/") || FFI::Platform.windows?
                   path = ['/usr/lib/','/usr/local/lib/'].find do |pth|
                     File.exist?(pth + libname)
                   end
```
