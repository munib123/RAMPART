# CrossVul Fix Pair: Unintended Proxy or Intermediary ('Confused Deputy') in c
**Pair ID:** 4375_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-441
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4375_1`)

## Vulnerability Information & PoC

## Description
Unintended Proxy or Intermediary ('Confused Deputy') - If an attacker cannot directly contact a target, but the product has access to the target, then the attacker can send a request to the product and have it be forwarded to the target.

## Vulnerable Code
```c
Lines 72-108 of the vulnerable file.

int make_ioa_addr_from_full_string(const uint8_t* saddr, int default_port, ioa_addr *addr);
void addr_set_port(ioa_addr* addr, int port);
int addr_get_port(const ioa_addr* addr);
int addr_to_string(const ioa_addr* addr, uint8_t* saddr);
int addr_to_string_no_port(const ioa_addr* addr, uint8_t* saddr);

uint32_t hash_int32(uint32_t a);
uint64_t hash_int64(uint64_t a);

///////////////////////////////////////////

void ioa_addr_range_set(ioa_addr_range* range, const ioa_addr* addr_min, const ioa_addr* addr_max);
int addr_less_eq(const ioa_addr* addr1, const ioa_addr* addr2);
int ioa_addr_in_range(const ioa_addr_range* range, const ioa_addr* addr);
void ioa_addr_range_cpy(ioa_addr_range* dest, const ioa_addr_range* src);

/////// Check whether this is a good address //////////////

int ioa_addr_is_multicast(ioa_addr *a);
int ioa_addr_is_loopback(ioa_addr *addr);

/////// Map "public" address to "private" address //////////////

// Must be called only in a single-threaded context,
// before the program starts spawning threads:

void ioa_addr_add_mapping(ioa_addr *apub, ioa_addr *apriv);
void map_addr_from_public_to_private(const ioa_addr *public_addr, ioa_addr *private_addr);
void map_addr_from_private_to_public(const ioa_addr *private_addr, ioa_addr *public_addr);

///////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__IOADDR__
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,6 +89,7 @@
 
 int ioa_addr_is_multicast(ioa_addr *a);
 int ioa_addr_is_loopback(ioa_addr *addr);
+int ioa_addr_is_zero(ioa_addr *addr);
 
 /////// Map "public" address to "private" address //////////////
 
```
