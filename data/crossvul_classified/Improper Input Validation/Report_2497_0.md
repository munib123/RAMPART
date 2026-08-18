# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 2497_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2497_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 336-359 of the vulnerable file.


    return unless non_ruby

    if platforms.length == 1 then
      title = platforms.values.length == 1 ? 'Platform' : 'Platforms'
      entry << "    #{title}: #{platforms.values.sort.join ', '}\n"
    else
      entry << "    Platforms:\n"
      platforms.sort_by do |version,|
        version
      end.each do |version, pls|
        label = "        #{version}: "
        data = format_text pls.sort.join(', '), 68, label.length
        data[0, label.length] = label
        entry << data << "\n"
      end
    end
  end

  def spec_summary entry, spec
    entry << "\n\n" << format_text(spec.summary, 68, 4)
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -353,7 +353,8 @@
   end
 
   def spec_summary entry, spec
-    entry << "\n\n" << format_text(spec.summary, 68, 4)
+    summary = truncate_text(spec.summary, "the summary for #{spec.full_name}")
+    entry << "\n\n" << format_text(summary, 68, 4)
   end
 
 end
```
