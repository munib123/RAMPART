# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3660_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3660_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 314-355 of the vulnerable file.


        # then, security group chains and rules
        for security_group in security_groups:
            rules = db.security_group_rule_get_by_security_group(ctxt,
                                                          security_group['id'])

            for rule in rules:
                LOG.debug(_('Adding security group rule: %r'), rule,
                          instance=instance)

                if not rule.cidr:
                    version = 4
                else:
                    version = netutils.get_ip_version(rule.cidr)

                if version == 4:
                    fw_rules = ipv4_rules
                else:
                    fw_rules = ipv6_rules

                protocol = rule.protocol
                if version == 6 and rule.protocol == 'icmp':
                    protocol = 'icmpv6'

                args = ['-j ACCEPT']
                if protocol:
                    args += ['-p', protocol]

                if protocol in ['udp', 'tcp']:
                    args += self._build_tcp_udp_rule(rule, version)
                elif protocol == 'icmp':
                    args += self._build_icmp_rule(rule, version)
                if rule.cidr:
                    LOG.debug('Using cidr %r', rule.cidr, instance=instance)
                    args += ['-s', rule.cidr]
                    fw_rules += [' '.join(args)]
                else:
                    if rule['grantee_group']:
                        # FIXME(jkoelker) This needs to be ported up into
                        #                 the compute manager which already
                        #                 has access to a nw_api handle,
                        #                 and should be the only one making
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,8 +331,8 @@
                 else:
                     fw_rules = ipv6_rules
 
-                protocol = rule.protocol
-                if version == 6 and rule.protocol == 'icmp':
+                protocol = rule.protocol.lower()
+                if version == 6 and protocol == 'icmp':
                     protocol = 'icmpv6'
 
                 args = ['-j ACCEPT']
```
