# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 5020_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5020_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 1-31 of the vulnerable file.

require 'tftp/server'
require 'proxy/validations'

module Proxy::TFTP
  class Api < ::Sinatra::Base
    include ::Proxy::Log
    include ::Proxy::Validations
    helpers ::Proxy::Helpers
    authorize_with_trusted_hosts
    authorize_with_ssl_client

    helpers do
      def instantiate variant, mac=nil
        # Filenames must end in a hex representation of a mac address but only if mac is not empty
        log_halt 403, "Invalid MAC address: #{mac}"                  unless valid_mac?(mac) || mac.nil?
        log_halt 403, "Unrecognized pxeboot config type: #{variant}" unless defined? variant.capitalize
        eval "Proxy::TFTP::#{variant.capitalize}.new"
      end

      def create variant, mac
        tftp = instantiate variant, mac
        log_halt(400, "TFTP: Failed to create pxe config file: ") {tftp.set(mac, (params[:pxeconfig] || params[:syslinux_config]))}
      end
      def delete variant, mac
        tftp = instantiate variant, mac
        log_halt(400, "TFTP: Failed to delete pxe config file: ") {tftp.del(mac)}
      end
      def create_default variant
        tftp = instantiate variant
        log_halt(400, "TFTP: Failed to create PXE default file: ") { tftp.create_default params[:menu]}
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,13 +8,14 @@
     helpers ::Proxy::Helpers
     authorize_with_trusted_hosts
     authorize_with_ssl_client
+    VARIANTS = ["Syslinux", "Pxegrub", "Pxegrub2", "Ztp", "Poap"].freeze
 
     helpers do
       def instantiate variant, mac=nil
         # Filenames must end in a hex representation of a mac address but only if mac is not empty
         log_halt 403, "Invalid MAC address: #{mac}"                  unless valid_mac?(mac) || mac.nil?
-        log_halt 403, "Unrecognized pxeboot config type: #{variant}" unless defined? variant.capitalize
-        eval "Proxy::TFTP::#{variant.capitalize}.new"
+        log_halt 403, "Unrecognized pxeboot config type: #{variant}" unless VARIANTS.include?(variant.capitalize)
+        Object.const_get("Proxy").const_get('TFTP').const_get(variant.capitalize).new
       end
 
       def create variant, mac
```
