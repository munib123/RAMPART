# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 1939_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1939_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 361-400 of the vulnerable file.

      write_block = create_info_block(options[:write])

      if options[:format] || @format
        frames.write("#{options[:format] || @format}:#{current_path}", &write_block)
        move_to = current_path.chomp(File.extname(current_path)) + ".#{options[:format] || @format}"
        file.content_type = ::MiniMime.lookup_by_filename(move_to).content_type
        file.move_to(move_to, permissions, directory_permissions)
      else
        frames.write(current_path, &write_block)
      end

      destroy_image(frames)
    rescue ::Magick::ImageMagickError => e
      raise CarrierWave::ProcessingError, I18n.translate(:"errors.messages.rmagick_processing_error", :e => e)
    end

  private

    def create_info_block(options)
      return nil unless options
      assignments = options.map { |k, v| "img.#{k} = #{v}" }
      code = "lambda { |img| " + assignments.join(";") + "}"
      eval code
    end

    def destroy_image(image)
      image.try(:destroy!)
    end

    def dimension_from(value)
      return value unless value.instance_of?(Proc)
      value.arity >= 1 ? value.call(self) : value.call
    end

    def rmagick_image
      ::Magick::Image.from_blob(self.read).first
    end

  end # RMagick
end # CarrierWave
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,9 +378,15 @@
 
     def create_info_block(options)
       return nil unless options
-      assignments = options.map { |k, v| "img.#{k} = #{v}" }
-      code = "lambda { |img| " + assignments.join(";") + "}"
-      eval code
+      proc do |img|
+        options.each do |k, v|
+          if v.is_a?(String) && (matches = v.match(/^["'](.+)["']/))
+            ActiveSupport::Deprecation.warn "Passing quoted strings like #{v} to #manipulate! is deprecated, pass them without quoting."
+            v = matches[1]
+          end
+          img.public_send(:"#{k}=", v)
+        end
+      end
     end
 
     def destroy_image(image)
```
