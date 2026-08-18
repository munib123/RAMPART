# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 956_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `956_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 65-110 of the vulnerable file.

        image.path.replace output_path
      end
    end

    ##
    # Opens a specific image file either on the local file system or at a URI.
    # Use this if you don't want to overwrite the image file.
    #
    # Extension is either guessed from the path or you can specify it as a
    # second parameter.
    #
    # @param path_or_url [String] Either a local file path or a URL that
    #   open-uri can read
    # @param ext [String] Specify the extension you want to read it as
    # @param options [Hash] Specify options for the open method
    # @return [MiniMagick::Image] The loaded image
    #
    def self.open(path_or_url, ext = nil, options = {})
      options, ext = ext, nil if ext.is_a?(Hash)

      ext ||=
        if File.exist?(path_or_url)
          File.extname(path_or_url)
        else
          File.extname(URI(path_or_url).path)
        end

      ext.sub!(/:.*/, '') # hack for filenames or URLs that include a colon

      Kernel.open(path_or_url, "rb", options) do |file|
        read(file, ext)
      end
    end

    ##
    # Used to create a new Image object data-copy. Not used to "paint" or
    # that kind of thing.
    #
    # Takes an extension in a block and can be used to build a new Image
    # object. Used by both {.open} and {.read} to create a new object. Ensures
    # we have a good tempfile.
    #
    # @param ext [String] Specify the extension you want to read it as
    # @param validate [Boolean] If false, skips validation of the created
    #   image. Defaults to true.
    # @yield [Tempfile] You can #write bits to this object to create the new
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,17 +82,15 @@
     def self.open(path_or_url, ext = nil, options = {})
       options, ext = ext, nil if ext.is_a?(Hash)
 
-      ext ||=
-        if File.exist?(path_or_url)
-          File.extname(path_or_url)
-        else
-          File.extname(URI(path_or_url).path)
-        end
-
+      uri = URI(path_or_url.to_s)
+
+      ext ||= File.extname(uri.path)
       ext.sub!(/:.*/, '') # hack for filenames or URLs that include a colon
 
-      Kernel.open(path_or_url, "rb", options) do |file|
-        read(file, ext)
+      if uri.is_a?(URI::HTTP) || uri.is_a?(URI::FTP)
+        uri.open(options) { |file| read(file, ext) }
+      else
+        File.open(uri.to_s, "rb", options) { |file| read(file, ext) }
       end
     end
 
```
