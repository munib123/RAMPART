# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in ruby
**Pair ID:** 1750_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1750_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

module Colorscore
  class Histogram
    def initialize(image_path, colors=16, depth=8)
      output = `convert #{image_path} -resize 400x400 -format %c -dither None -quantize YIQ -colors #{colors} -depth #{depth} histogram:info:-`
      @lines = output.lines.sort.reverse.map(&:strip).reject(&:empty?)
    end

    # Returns an array of colors in descending order of occurances.
    def colors
      hex_values = @lines.map { |line| line[/#([0-9A-F]{6}) /, 1] }.compact
      hex_values.map { |hex| Color::RGB.from_html(hex) }
    end

    def color_counts
      @lines.map { |line| line.split(':')[0].to_i }
    end

    def scores
      total = color_counts.inject(:+).to_f
      scores = color_counts.map { |count| count / total }
      scores.zip(colors)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,9 @@
+require "shellwords"
+
 module Colorscore
   class Histogram
     def initialize(image_path, colors=16, depth=8)
-      output = `convert #{image_path} -resize 400x400 -format %c -dither None -quantize YIQ -colors #{colors} -depth #{depth} histogram:info:-`
+      output = `convert #{image_path.shellescape} -resize 400x400 -format %c -dither None -quantize YIQ -colors #{colors.to_i} -depth #{depth.to_i} histogram:info:-`
       @lines = output.lines.sort.reverse.map(&:strip).reject(&:empty?)
     end
 
```
