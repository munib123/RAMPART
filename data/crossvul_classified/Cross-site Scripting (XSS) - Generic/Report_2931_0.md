# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 2931_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2931_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 290-330 of the vulnerable file.

      settings.rubygems_proxy ? combined_gem_list : local_gem_list
    end

    def query_gems
      params[:gems].to_s.split(',')
    end

    def local_gem_list
      query_gems.map{|query_gem| gem_dependencies(query_gem) }.flatten(1)
    end

    def remote_gem_list
      RubygemsDependency.for(*query_gems)
    end

    def combined_gem_list
      GemListMerge.from(local_gem_list, remote_gem_list)
    end

    helpers do
      def h(text)
        Rack::Utils.escape_html(text)
      end

      def spec_for(gem_name, version, platform = default_platform)
        filename = [gem_name, version]
        filename.push(platform) if platform != default_platform
        spec_file = File.join(settings.data, "quick", "Marshal.#{Gem.marshal_version}", "#{filename.join("-")}.gemspec.rz")
        File::open(spec_file, 'r') do |unzipped_spec_file|
          unzipped_spec_file.binmode
          Marshal.load(Gem.inflate(unzipped_spec_file.read))
        end if File.exist? spec_file
      end

      def default_platform
        'ruby'
      end

      # Return a list of versions of gem 'gem_name' with the dependencies of each version.
      def gem_dependencies(gem_name)
        dependency_cache.marshal_cache(gem_name) do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -307,6 +307,15 @@
     end
 
     helpers do
+      def href(text)
+        escaped_text = Rack::Utils.escape_html(text)
+        if escaped_text.start_with?('http://') || escaped_text.start_with?('https://')
+          escaped_text
+        else
+          '#'
+        end
+      end
+
       def h(text)
         Rack::Utils.escape_html(text)
       end
```
