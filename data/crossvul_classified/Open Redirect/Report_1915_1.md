# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in yaml
**Pair ID:** 1915_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```yaml
Lines 625-667 of the vulnerable file.

# openssl s_client -connect $host:$port < /dev/null 2> /dev/null |
#   openssl x509 -outform DER | openssl sha256 -binary | base64 | tr -d '='
# or by checking matrix.org/federationtester/api/report?server_name=$host
#
#tls_fingerprints: [{"sha256": "<base64_encoded_sha256_fingerprint>"}]


## Federation ##

# Restrict federation to the following whitelist of domains.
# N.B. we recommend also firewalling your federation listener to limit
# inbound federation traffic as early as possible, rather than relying
# purely on this application-layer restriction.  If not specified, the
# default is to whitelist everything.
#
#federation_domain_whitelist:
#  - lon.example.com
#  - nyc.example.com
#  - syd.example.com

# Prevent federation requests from being sent to the following
# blacklist IP address CIDR ranges. If this option is not specified, or
# specified with an empty list, no ip range blacklist will be enforced.
#
# As of Synapse v1.4.0 this option also affects any outbound requests to identity
# servers provided by user input.
#
# (0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
# listed here, since they correspond to unroutable addresses.)
#
federation_ip_range_blacklist:
  - '127.0.0.0/8'
  - '10.0.0.0/8'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - '100.64.0.0/10'
  - '169.254.0.0/16'
  - '::1/128'
  - 'fe80::/64'
  - 'fc00::/7'

# Report prometheus metrics on the age of PDUs being sent to and received from
# the following domains. This can be used to give an idea of "delay" on inbound
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -642,17 +642,19 @@
 #  - nyc.example.com
 #  - syd.example.com
 
-# Prevent federation requests from being sent to the following
-# blacklist IP address CIDR ranges. If this option is not specified, or
-# specified with an empty list, no ip range blacklist will be enforced.
-#
-# As of Synapse v1.4.0 this option also affects any outbound requests to identity
-# servers provided by user input.
+# Prevent outgoing requests from being sent to the following blacklisted IP address
+# CIDR ranges. If this option is not specified, or specified with an empty list,
+# no IP range blacklist will be enforced.
+#
+# The blacklist applies to the outbound requests for federation, identity servers,
+# push servers, and for checking key validitity for third-party invite events.
 #
 # (0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
 # listed here, since they correspond to unroutable addresses.)
 #
-federation_ip_range_blacklist:
+# This option replaces federation_ip_range_blacklist in Synapse v1.24.0.
+#
+ip_range_blacklist:
   - '127.0.0.0/8'
   - '10.0.0.0/8'
   - '172.16.0.0/12'
```
