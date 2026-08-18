# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in ruby
**Pair ID:** 567_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `567_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module PrivateAddressCheck
  PrivateConnectionAttemptedError = Class.new(StandardError)

  module_function

  def only_public_connections
    Thread.current[:private_address_check] = true
    yield
  ensure
    Thread.current[:private_address_check] = false
  end
end

TCPSocket.class_eval do
  alias initialize_without_private_address_check initialize

  def initialize(remote_host, remote_port, local_host = nil, local_port = nil)
    if Thread.current[:private_address_check] && PrivateAddressCheck.resolves_to_private_address?(remote_host)
      raise PrivateAddressCheck::PrivateConnectionAttemptedError
    end

    initialize_without_private_address_check(remote_host, remote_port, local_host, local_port)
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,11 +14,10 @@
 TCPSocket.class_eval do
   alias initialize_without_private_address_check initialize
 
-  def initialize(remote_host, remote_port, local_host = nil, local_port = nil)
-    if Thread.current[:private_address_check] && PrivateAddressCheck.resolves_to_private_address?(remote_host)
+  def initialize(*args)
+    initialize_without_private_address_check(*args)
+    if Thread.current[:private_address_check] && PrivateAddressCheck.resolves_to_private_address?(remote_address.ip_address)
       raise PrivateAddressCheck::PrivateConnectionAttemptedError
     end
-
-    initialize_without_private_address_check(remote_host, remote_port, local_host, local_port)
   end
 end
```
