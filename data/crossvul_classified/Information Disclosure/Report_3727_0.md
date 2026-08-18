# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3727_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3727_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 214-243 of the vulnerable file.

        Puppet::Util::Log.level = :debug
      else
        Puppet::Util::Log.level = :info
      end

      unless Puppet[:daemonize] or options[:rack]
        Puppet::Util::Log.newdestination(:console)
        options[:setdest] = true
      end
    end

    Puppet::Util::Log.newdestination(:syslog) unless options[:setdest]

    exit(Puppet.settings.print_configs ? 0 : 1) if Puppet.settings.print_configs?

    Puppet.settings.use :main, :master, :ssl, :metrics

    # Cache our nodes in yaml.  Currently not configurable.
    Puppet::Node.indirection.cache_class = :yaml

    # Configure all of the SSL stuff.
    if Puppet::SSL::CertificateAuthority.ca?
      Puppet::SSL::Host.ca_location = :local
      Puppet.settings.use :ca
      Puppet::SSL::CertificateAuthority.instance
    else
      Puppet::SSL::Host.ca_location = :none
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -231,6 +231,9 @@
     # Cache our nodes in yaml.  Currently not configurable.
     Puppet::Node.indirection.cache_class = :yaml
 
+    Puppet::FileServing::Content.indirection.terminus_class = :file_server
+    Puppet::FileServing::Metadata.indirection.terminus_class = :file_server
+
     # Configure all of the SSL stuff.
     if Puppet::SSL::CertificateAuthority.ca?
       Puppet::SSL::Host.ca_location = :local
```
