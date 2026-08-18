# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5041_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5041_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-11 of the vulnerable file.

class Rack::MiniProfiler::Context
  attr_accessor :inject_js,:current_timer,:page_struct,:skip_backtrace,:full_backtrace,:discard, :mpt_init, :measure

  def initialize(opts = {})
    opts["measure"] = true unless opts.key? "measure"
    opts.each do |k,v|
      self.instance_variable_set('@' + k, v)
    end
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 class Rack::MiniProfiler::Context
-  attr_accessor :inject_js,:current_timer,:page_struct,:skip_backtrace,:full_backtrace,:discard, :mpt_init, :measure
+  attr_accessor :inject_js,:current_timer,:page_struct,:skip_backtrace,
+                :full_backtrace,:discard, :mpt_init, :measure
 
   def initialize(opts = {})
     opts["measure"] = true unless opts.key? "measure"
```
