# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 863_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `863_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 339-379 of the vulnerable file.

{
	int proto, r;
	char iaddr_old[32];
	char rhost_old[32];
	unsigned short iport_old;
	struct in_addr address;
	unsigned int timestamp;

	proto = proto_atoi(protocol);
	if(inet_aton(iaddr, &address) <= 0) {
		syslog(LOG_ERR, "inet_aton(%s) FAILED", iaddr);
		return -1;
	}

	if(!check_upnp_rule_against_permissions(upnppermlist, num_upnpperm,
	                                        eport, address, iport)) {
		syslog(LOG_INFO, "redirection permission check failed for "
		                 "%hu->%s:%hu %s", eport, iaddr, iport, protocol);
		return -3;
	}
	/* IGDv1 (WANIPConnection:1 Service Template Version 1.01 / Nov 12, 2001)
	 * - 2.2.20.PortMappingDescription :
	 *  Overwriting Previous / Existing Port Mappings:
	 * If the RemoteHost, ExternalPort, PortMappingProtocol and InternalClient
	 * are exactly the same as an existing mapping, the existing mapping values
	 * for InternalPort, PortMappingDescription, PortMappingEnabled and
	 * PortMappingLeaseDuration are overwritten.
	 *  Rejecting a New Port Mapping:
	 * In cases where the RemoteHost, ExternalPort and PortMappingProtocol
	 * are the same as an existing mapping, but the InternalClient is
	 * different, the action is rejected with an appropriate error.
	 *  Add or Reject New Port Mapping behavior based on vendor implementation:
	 * In cases where the ExternalPort, PortMappingProtocol and InternalClient
	 * are the same, but RemoteHost is different, the vendor can choose to
	 * support both mappings simultaneously, or reject the second mapping
	 * with an appropriate error.
	 *
	 * - 2.4.16.AddPortMapping
	 * This action creates a new port mapping or overwrites an existing
	 * mapping with the same internal client. If the ExternalPort and
	 * PortMappingProtocol pair is already mapped to another internal client,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -356,6 +356,10 @@
 		                 "%hu->%s:%hu %s", eport, iaddr, iport, protocol);
 		return -3;
 	}
+
+	if (desc == NULL)
+		desc = "";	/* assume empty description */
+
 	/* IGDv1 (WANIPConnection:1 Service Template Version 1.01 / Nov 12, 2001)
 	 * - 2.2.20.PortMappingDescription :
 	 *  Overwriting Previous / Existing Port Mappings:
```
