# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3727_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3727_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 47-87 of the vulnerable file.

    @mounts = {}
    @config_file = nil

    # We don't check to see if the file is modified the first time,
    # because we always want to parse at first.
    readconfig(false)
  end

  # Is a given mount available?
  def mounted?(name)
    @mounts.include?(name)
  end

  # Split the path into the separate mount point and path.
  def split_path(request)
    # Reparse the configuration if necessary.
    readconfig

    mount_name, path = request.key.split(File::Separator, 2)

    raise(ArgumentError, "Cannot find file: Invalid path '#{mount_name}'") unless mount_name =~ %r{^[-\w]+$}

    return nil unless mount = find_mount(mount_name, request.environment)
    if mount.name == "modules" and mount_name != "modules"
      # yay backward-compatibility
      path = "#{mount_name}/#{path}"
    end

    if path == ""
      path = nil
    elsif path
      # Remove any double slashes that might have occurred
      path = path.gsub(/\/+/, "/")
    end

    return mount, path
  end

  def umount(name)
    @mounts.delete(name) if @mounts.include? name
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
 
     mount_name, path = request.key.split(File::Separator, 2)
 
-    raise(ArgumentError, "Cannot find file: Invalid path '#{mount_name}'") unless mount_name =~ %r{^[-\w]+$}
+    raise(ArgumentError, "Cannot find file: Invalid mount '#{mount_name}'") unless mount_name =~ %r{^[-\w]+$}
 
     return nil unless mount = find_mount(mount_name, request.environment)
     if mount.name == "modules" and mount_name != "modules"
```
