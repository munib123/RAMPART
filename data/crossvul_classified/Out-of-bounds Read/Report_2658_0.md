# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2658_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2658_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 164-202 of the vulnerable file.

#define IP6OPT_MUTABLE		0x20

/* Routing header */
struct ip6_rthdr {
	uint8_t  ip6r_nxt;	/* next header */
	uint8_t  ip6r_len;	/* length in units of 8 octets */
	uint8_t  ip6r_type;	/* routing type */
	uint8_t  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
} UNALIGNED;

#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RTHDR_TYPE_2 2

/* Type 0 Routing header */
/* Also used for Type 2 */
struct ip6_rthdr0 {
	uint8_t  ip6r0_nxt;		/* next header */
	uint8_t  ip6r0_len;		/* length in units of 8 octets */
	uint8_t  ip6r0_type;		/* always zero */
	uint8_t  ip6r0_segleft;	/* segments left */
	uint8_t  ip6r0_reserved;	/* reserved field */
	uint8_t  ip6r0_slmap[3];	/* strict/loose bit map */
	struct in6_addr ip6r0_addr[1];	/* up to 23 addresses */
} UNALIGNED;

/* Fragment header */
struct ip6_frag {
	uint8_t  ip6f_nxt;		/* next header */
	uint8_t  ip6f_reserved;	/* reserved field */
	uint16_t ip6f_offlg;		/* offset, reserved, and flag */
	uint32_t ip6f_ident;		/* identification */
} UNALIGNED;

#define IP6F_OFF_MASK		0xfff8	/* mask out offset from ip6f_offlg */
#define IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001	/* more-fragments flag */

#endif /* not _NETINET_IP6_H_ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,9 +181,8 @@
 	uint8_t  ip6r0_nxt;		/* next header */
 	uint8_t  ip6r0_len;		/* length in units of 8 octets */
 	uint8_t  ip6r0_type;		/* always zero */
-	uint8_t  ip6r0_segleft;	/* segments left */
-	uint8_t  ip6r0_reserved;	/* reserved field */
-	uint8_t  ip6r0_slmap[3];	/* strict/loose bit map */
+	uint8_t  ip6r0_segleft;		/* segments left */
+	uint32_t ip6r0_reserved;	/* reserved field */
 	struct in6_addr ip6r0_addr[1];	/* up to 23 addresses */
 } UNALIGNED;
 
```
