# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 237-277 of the vulnerable file.

          log_metadata_inlining

          # If the file is in the environment directory, we can safely inline
          catalog.metadata[resource.title] = metadata
        else
          # Log a profiler event that we skipped this file because it is not in an environment.
          log_file_outside_environment
        end
      end
    end
  end

  # Compile the actual catalog.
  def compile(node, options)
    if node.environment && node.environment.static_catalogs? && options[:static_catalog] && options[:code_id]
      # Check for errors before compiling the catalog
      checksum_type = common_checksum_type(options[:checksum_type])
      raise Puppet::Error, "Unable to find a common checksum type between agent '#{options[:checksum_type]}' and master '#{known_checksum_types}'." unless checksum_type
    end

    str = "Compiled %s for #{node.name}" % [checksum_type ? 'static catalog' : 'catalog']
    str += " in environment #{node.environment}" if node.environment
    config = nil

    benchmark(:notice, str) do
      compile_type = checksum_type ? :static_compile : :compile
      Puppet::Util::Profiler.profile(str, [:compiler, compile_type, node.environment, node.name]) do
        begin
          config = Puppet::Parser::Compiler.compile(node, options[:code_id])
        rescue Puppet::Error => detail
          Puppet.err(detail.to_s) if networked?
          raise
        end

        if checksum_type && config.is_a?(model)
          str = "Inlined resource metadata into static catalog for #{node.name}"
          str += " in environment #{node.environment}" if node.environment
          benchmark(:notice, str) do
            Puppet::Util::Profiler.profile(str, [:compiler, :static_compile_postprocessing, node.environment, node.name]) do
              inline_metadata(config, checksum_type)
            end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,7 +254,8 @@
       raise Puppet::Error, "Unable to find a common checksum type between agent '#{options[:checksum_type]}' and master '#{known_checksum_types}'." unless checksum_type
     end
 
-    str = "Compiled %s for #{node.name}" % [checksum_type ? 'static catalog' : 'catalog']
+    str = "Compiled %s for " % [checksum_type ? 'static catalog' : 'catalog']
+    str += node.name
     str += " in environment #{node.environment}" if node.environment
     config = nil
 
```
