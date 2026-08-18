# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1540_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1540_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-28 of the vulnerable file.

require "paperclip"

module Paperclip
  class Cropper < Thumbnail

    def transformation_command
      if crop_command
        crop_command + super.join(' ').sub(/ -crop \S+/, '').split(' ')
      else
        super
      end
    end


    def crop_command
      target = @attachment.instance

      if target.cropping?(@attachment.name)
        w = target.send :"#{@attachment.name}_crop_w"
        h = target.send :"#{@attachment.name}_crop_h"
        x = target.send :"#{@attachment.name}_crop_x"
        y = target.send :"#{@attachment.name}_crop_y"
        ["-crop", "#{w}x#{h}+#{x}+#{y}"]
      end
    end

  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,11 +16,16 @@
       target = @attachment.instance
 
       if target.cropping?(@attachment.name)
-        w = target.send :"#{@attachment.name}_crop_w"
-        h = target.send :"#{@attachment.name}_crop_h"
-        x = target.send :"#{@attachment.name}_crop_x"
-        y = target.send :"#{@attachment.name}_crop_y"
-        ["-crop", "#{w}x#{h}+#{x}+#{y}"]
+        begin
+          w = Integer(target.send :"#{@attachment.name}_crop_w")
+          h = Integer(target.send :"#{@attachment.name}_crop_h")
+          x = Integer(target.send :"#{@attachment.name}_crop_x")
+          y = Integer(target.send :"#{@attachment.name}_crop_y")
+          ["-crop", "#{w}x#{h}+#{x}+#{y}"]
+        rescue
+          Paperclip.log("[papercrop] #{@attachment.name} crop w/h/x/y were non-integer")
+          return
+        end
       end
     end
 
```
