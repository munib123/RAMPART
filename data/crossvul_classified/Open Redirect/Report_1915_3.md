# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_3
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_3`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 19-61 of the vulnerable file.


from synapse.config._base import Config, ConfigError
from synapse.config._util import validate_config


class FederationConfig(Config):
    section = "federation"

    def read_config(self, config, **kwargs):
        # FIXME: federation_domain_whitelist needs sytests
        self.federation_domain_whitelist = None  # type: Optional[dict]
        federation_domain_whitelist = config.get("federation_domain_whitelist", None)

        if federation_domain_whitelist is not None:
            # turn the whitelist into a hash for speed of lookup
            self.federation_domain_whitelist = {}

            for domain in federation_domain_whitelist:
                self.federation_domain_whitelist[domain] = True

        self.federation_ip_range_blacklist = config.get(
            "federation_ip_range_blacklist", []
        )

        # Attempt to create an IPSet from the given ranges
        try:
            self.federation_ip_range_blacklist = IPSet(
                self.federation_ip_range_blacklist
            )

            # Always blacklist 0.0.0.0, ::
            self.federation_ip_range_blacklist.update(["0.0.0.0", "::"])
        except Exception as e:
            raise ConfigError(
                "Invalid range(s) provided in federation_ip_range_blacklist: %s" % e
            )

        federation_metrics_domains = config.get("federation_metrics_domains") or []
        validate_config(
            _METRICS_FOR_DOMAINS_SCHEMA,
            federation_metrics_domains,
            ("federation_metrics_domains",),
        )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,22 +36,30 @@
             for domain in federation_domain_whitelist:
                 self.federation_domain_whitelist[domain] = True
 
-        self.federation_ip_range_blacklist = config.get(
-            "federation_ip_range_blacklist", []
-        )
+        ip_range_blacklist = config.get("ip_range_blacklist", [])
 
         # Attempt to create an IPSet from the given ranges
         try:
-            self.federation_ip_range_blacklist = IPSet(
-                self.federation_ip_range_blacklist
-            )
+            self.ip_range_blacklist = IPSet(ip_range_blacklist)
+        except Exception as e:
+            raise ConfigError("Invalid range(s) provided in ip_range_blacklist: %s" % e)
+        # Always blacklist 0.0.0.0, ::
+        self.ip_range_blacklist.update(["0.0.0.0", "::"])
 
-            # Always blacklist 0.0.0.0, ::
-            self.federation_ip_range_blacklist.update(["0.0.0.0", "::"])
+        # The federation_ip_range_blacklist is used for backwards-compatibility
+        # and only applies to federation and identity servers. If it is not given,
+        # default to ip_range_blacklist.
+        federation_ip_range_blacklist = config.get(
+            "federation_ip_range_blacklist", ip_range_blacklist
+        )
+        try:
+            self.federation_ip_range_blacklist = IPSet(federation_ip_range_blacklist)
         except Exception as e:
             raise ConfigError(
                 "Invalid range(s) provided in federation_ip_range_blacklist: %s" % e
             )
+        # Always blacklist 0.0.0.0, ::
+        self.federation_ip_range_blacklist.update(["0.0.0.0", "::"])
 
         federation_metrics_domains = config.get("federation_metrics_domains") or []
         validate_config(
@@ -76,17 +84,19 @@
         #  - nyc.example.com
         #  - syd.example.com
 
-        # Prevent federation requests from being sent to the following
-        # blacklist IP address CIDR ranges. If this option is not specified, or
-        # specified with an empty list, no ip range blacklist will be enforced.
+        # Prevent outgoing requests from being sent to the following blacklisted IP address
+        # CIDR ranges. If this option is not specified, or specified with an empty list,
+        # no IP range blacklist will be enforced.
         #
-        # As of Synapse v1.4.0 this option also affects any outbound requests to identity
-        # servers provided by user input.
+        # The blacklist applies to the outbound requests for federation, identity servers,
+        # push servers, and for checking key validitity for third-party invite events.
         #
         # (0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
         # listed here, since they correspond to unroutable addresses.)
         #
-        federation_ip_range_blacklist:
+        # This option replaces federation_ip_range_blacklist in Synapse v1.24.0.
+        #
+        ip_range_blacklist:
           - '127.0.0.0/8'
           - '10.0.0.0/8'
           - '172.16.0.0/12'
```
