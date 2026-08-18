# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 2496_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2496_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 209-249 of the vulnerable file.

    versions.each do |gem_name, matching_tuples|
      matching_tuples = matching_tuples.sort_by { |n,_| n.version }.reverse

      platforms = Hash.new { |h,version| h[version] = [] }

      matching_tuples.each do |n, _|
        platforms[n.version] << n.platform if n.platform
      end

      seen = {}

      matching_tuples.delete_if do |n,_|
        if seen[n.version] then
          true
        else
          seen[n.version] = true
          false
        end
      end

      output << make_entry(matching_tuples, platforms)
    end
  end

  def entry_details entry, detail_tuple, specs, platforms
    return unless options[:details]

    name_tuple, spec = detail_tuple

    spec = spec.fetch_spec name_tuple if spec.respond_to? :fetch_spec

    entry << "\n"

    spec_platforms   entry, platforms
    spec_authors     entry, spec
    spec_homepage    entry, spec
    spec_license     entry, spec
    spec_loaded_from entry, spec, specs
    spec_summary     entry, spec
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,7 +226,7 @@
         end
       end
 
-      output << make_entry(matching_tuples, platforms)
+      output << clean_text(make_entry(matching_tuples, platforms))
     end
   end
 
```
