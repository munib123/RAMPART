# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in ruby
**Pair ID:** 11_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `11_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```ruby
Lines 87-132 of the vulnerable file.

                  'A6'   + # magic
                  'A2'   + # version
                  'A32'  + # uname
                  'A32'  + # gname
                  'A8'   + # devmajor
                  'A8'   + # devminor
                  'A155'   # prefix

  attr_reader(*FIELDS)

  ##
  # Creates a tar header from IO +stream+

  def self.from(stream)
    header = stream.read 512
    empty = (header == "\0" * 512)

    fields = header.unpack UNPACK_FORMAT

    new :name     => fields.shift,
        :mode     => fields.shift.oct,
        :uid      => fields.shift.oct,
        :gid      => fields.shift.oct,
        :size     => fields.shift.oct,
        :mtime    => fields.shift.oct,
        :checksum => fields.shift.oct,
        :typeflag => fields.shift,
        :linkname => fields.shift,
        :magic    => fields.shift,
        :version  => fields.shift.oct,
        :uname    => fields.shift,
        :gname    => fields.shift,
        :devmajor => fields.shift.oct,
        :devminor => fields.shift.oct,
        :prefix   => fields.shift,

        :empty => empty
  end

  ##
  # Creates a new TarHeader using +vals+

  def initialize(vals)
    unless vals[:name] && vals[:size] && vals[:prefix] && vals[:mode] then
      raise ArgumentError, ":name, :size, :prefix and :mode required"
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,23 +104,28 @@
     fields = header.unpack UNPACK_FORMAT
 
     new :name     => fields.shift,
-        :mode     => fields.shift.oct,
-        :uid      => fields.shift.oct,
-        :gid      => fields.shift.oct,
-        :size     => fields.shift.oct,
-        :mtime    => fields.shift.oct,
-        :checksum => fields.shift.oct,
+        :mode     => strict_oct(fields.shift),
+        :uid      => strict_oct(fields.shift),
+        :gid      => strict_oct(fields.shift),
+        :size     => strict_oct(fields.shift),
+        :mtime    => strict_oct(fields.shift),
+        :checksum => strict_oct(fields.shift),
         :typeflag => fields.shift,
         :linkname => fields.shift,
         :magic    => fields.shift,
-        :version  => fields.shift.oct,
+        :version  => strict_oct(fields.shift),
         :uname    => fields.shift,
         :gname    => fields.shift,
-        :devmajor => fields.shift.oct,
-        :devminor => fields.shift.oct,
+        :devmajor => strict_oct(fields.shift),
+        :devminor => strict_oct(fields.shift),
         :prefix   => fields.shift,
 
         :empty => empty
+  end
+
+  def self.strict_oct(str)
+    return str.oct if str =~ /\A[0-7]*\z/
+    raise ArgumentError, "#{str.inspect} is not an octal string"
   end
 
   ##
```
