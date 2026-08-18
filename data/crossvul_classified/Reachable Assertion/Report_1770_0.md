# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 1770_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1770_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 181-221 of the vulnerable file.

lldpd_alloc_mgmt(int family, void *addrptr, size_t addrsize, u_int32_t iface)
{
	struct lldpd_mgmt *mgmt;

	log_debug("alloc", "allocate a new management address (family: %d)", family);

	if (family <= LLDPD_AF_UNSPEC || family >= LLDPD_AF_LAST) {
		errno = EAFNOSUPPORT;
		return NULL;
	}
	if (addrsize > LLDPD_MGMT_MAXADDRSIZE) {
		errno = EOVERFLOW;
		return NULL;
	}
	mgmt = calloc(1, sizeof(struct lldpd_mgmt));
	if (mgmt == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	mgmt->m_family = family;
	assert(addrsize <= LLDPD_MGMT_MAXADDRSIZE);
	memcpy(&mgmt->m_addr, addrptr, addrsize);
	mgmt->m_addrsize = addrsize;
	mgmt->m_iface = iface;
	return mgmt;
}

void
lldpd_hardware_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	log_debug("alloc", "cleanup hardware port %s", hardware->h_ifname);

	free(hardware->h_lport_previous);
	free(hardware->h_lchassis_previous_id);
	free(hardware->h_lport_previous_id);
	lldpd_port_cleanup(&hardware->h_lport, 1);
	if (hardware->h_ops && hardware->h_ops->cleanup)
		hardware->h_ops->cleanup(cfg, hardware);
	levent_hardware_release(hardware);
	free(hardware);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,7 +198,6 @@
 		return NULL;
 	}
 	mgmt->m_family = family;
-	assert(addrsize <= LLDPD_MGMT_MAXADDRSIZE);
 	memcpy(&mgmt->m_addr, addrptr, addrsize);
 	mgmt->m_addrsize = addrsize;
 	mgmt->m_iface = iface;
```
