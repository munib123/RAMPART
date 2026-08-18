# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in ruby
**Pair ID:** 2501_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2501_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```ruby
Lines 14-38 of the vulnerable file.

    # Link Local,
    IPAddr.new("169.254.0.0/16"),

    # RFC 1918
    IPAddr.new("10.0.0.0/8"),
    IPAddr.new("172.16.0.0/12"),
    IPAddr.new("192.168.0.0/16"),

    # RFC 4193
    IPAddr.new("fc00::/7"),
  ]

  def private_address?(address)
    CIDR_LIST.any? do |cidr| 
      cidr.include?(address)
    end
  end

  def resolves_to_private_address?(hostname)
    ips = Resolv.getaddresses(hostname)
    ips.any? do |ip| 
      private_address?(ip)
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,8 @@
 
   def resolves_to_private_address?(hostname)
     ips = Resolv.getaddresses(hostname)
+    return true if ips.empty?
+
     ips.any? do |ip| 
       private_address?(ip)
     end
```
