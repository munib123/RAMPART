# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4048_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4048_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 93-133 of the vulnerable file.

        end
      end

      def handle_extension(name, opts, body, type, line_no = nil)
        case name
        when 'comment'
          if body.kind_of?(String)
            @tree.children << Element.new(:comment, body, nil, category: type, location: line_no)
          end
          true
        when 'nomarkdown'
          if body.kind_of?(String)
            @tree.children << Element.new(:raw, body, nil, category: type,
                                          location: line_no, type: opts['type'].to_s.split(/\s+/))
          end
          true
        when 'options'
          opts.select do |k, v|
            k = k.to_sym
            if Kramdown::Options.defined?(k)
              begin
                val = Kramdown::Options.parse(k, v)
                @options[k] = val
                (@root.options[:options] ||= {})[k] = val
              rescue StandardError
              end
              false
            else
              true
            end
          end.each do |k, _v|
            warning("Unknown kramdown option '#{k}'")
          end
          @tree.children << new_block_el(:eob, :extension) if type == :block
          true
        else
          false
        end
      end

      ALD_ID_CHARS = /[\w-]/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,6 +110,12 @@
           opts.select do |k, v|
             k = k.to_sym
             if Kramdown::Options.defined?(k)
+              if @options[:forbidden_inline_options].include?(k) ||
+                  k == :forbidden_inline_options
+                warning("Option #{k} may not be set inline")
+                next false
+              end
+
               begin
                 val = Kramdown::Options.parse(k, v)
                 @options[k] = val
```
