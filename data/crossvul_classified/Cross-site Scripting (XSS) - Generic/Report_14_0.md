# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 14_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `14_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 615-655 of the vulnerable file.

        }
      }

      deps = deps.sort_by { |dep| [dep["name"].downcase, dep["version"]] }
      deps.last["is_last"] = true unless deps.empty?

      # executables
      executables = spec.executables.sort.collect { |exec| {"executable" => exec} }
      executables = nil if executables.empty?
      executables.last["is_last"] = true if executables

      specs << {
        "authors"             => spec.authors.sort.join(", "),
        "date"                => spec.date.to_s,
        "dependencies"        => deps,
        "doc_path"            => doc_root(spec.full_name),
        "executables"         => executables,
        "only_one_executable" => (executables && executables.size == 1),
        "full_name"           => spec.full_name,
        "has_deps"            => !deps.empty?,
        "homepage"            => spec.homepage,
        "name"                => spec.name,
        "rdoc_installed"      => Gem::RDoc.new(spec).rdoc_installed?,
        "ri_installed"        => Gem::RDoc.new(spec).ri_installed?,
        "summary"             => spec.summary,
        "version"             => spec.version.to_s,
      }
    end

    specs << {
      "authors" => "Chad Fowler, Rich Kilmer, Jim Weirich, Eric Hodel and others",
      "dependencies" => [],
      "doc_path" => doc_root("rubygems-#{Gem::VERSION}"),
      "executables" => [{"executable" => 'gem', "is_last" => true}],
      "only_one_executable" => true,
      "full_name" => "rubygems-#{Gem::VERSION}",
      "has_deps" => false,
      "homepage" => "http://guides.rubygems.org/",
      "name" => 'rubygems',
      "ri_installed" => true,
      "summary" => "RubyGems itself",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -632,7 +632,7 @@
         "only_one_executable" => (executables && executables.size == 1),
         "full_name"           => spec.full_name,
         "has_deps"            => !deps.empty?,
-        "homepage"            => spec.homepage,
+        "homepage"            => (URI.parse(spec.homepage).is_a?(URI::HTTP) || URI.parse(spec.homepage).is_a?(URI::HTTPS)) ? spec.homepage : ".",
         "name"                => spec.name,
         "rdoc_installed"      => Gem::RDoc.new(spec).rdoc_installed?,
         "ri_installed"        => Gem::RDoc.new(spec).ri_installed?,
```
