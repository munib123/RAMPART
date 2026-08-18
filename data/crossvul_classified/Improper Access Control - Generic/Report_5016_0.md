# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5016_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5016_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 316-356 of the vulnerable file.

	int				hoplimit;
	struct icmp6_hdr *		icmp6_hdr;
	unsigned char *			opts_start; /* pointer to buf at the
						       place where opts start */
	union {
		struct ndp_msggeneric	generic;
		struct ndp_msgrs	rs;
		struct ndp_msgra	ra;
		struct ndp_msgns	ns;
		struct ndp_msgna	na;
		struct ndp_msgr		r;
	} nd_msg;
};

struct ndp_msg_type_info {
#define NDP_STRABBR_SIZE 4
	char strabbr[NDP_STRABBR_SIZE];
	uint8_t raw_type;
	size_t raw_struct_size;
	void (*addrto_adjust)(struct in6_addr *addr);
};

static void ndp_msg_addrto_adjust_all_nodes(struct in6_addr *addr)
{
	struct in6_addr any = IN6ADDR_ANY_INIT;

	if (memcmp(addr, &any, sizeof(any)))
		return;
	addr->s6_addr32[0] = htonl(0xFF020000);
	addr->s6_addr32[1] = 0;
	addr->s6_addr32[2] = 0;
	addr->s6_addr32[3] = htonl(0x1);
}

static void ndp_msg_addrto_adjust_all_routers(struct in6_addr *addr)
{
	struct in6_addr any = IN6ADDR_ANY_INIT;

	if (memcmp(addr, &any, sizeof(any)))
		return;
	addr->s6_addr32[0] = htonl(0xFF020000);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -333,6 +333,7 @@
 	uint8_t raw_type;
 	size_t raw_struct_size;
 	void (*addrto_adjust)(struct in6_addr *addr);
+	bool (*addrto_validate)(struct in6_addr *addr);
 };
 
 static void ndp_msg_addrto_adjust_all_nodes(struct in6_addr *addr)
@@ -357,6 +358,11 @@
 	addr->s6_addr32[1] = 0;
 	addr->s6_addr32[2] = 0;
 	addr->s6_addr32[3] = htonl(0x2);
+}
+
+static bool ndp_msg_addrto_validate_link_local(struct in6_addr *addr)
+{
+	return IN6_IS_ADDR_LINKLOCAL (addr);
 }
 
 static struct ndp_msg_type_info ndp_msg_type_info_list[] =
@@ -371,6 +377,7 @@
 		.strabbr = "RA",
 		.raw_type = ND_ROUTER_ADVERT,
 		.raw_struct_size = sizeof(struct nd_router_advert),
+		.addrto_validate = ndp_msg_addrto_validate_link_local,
 	},
 	[NDP_MSG_NS] = {
 		.strabbr = "NS",
@@ -387,6 +394,7 @@
 		.strabbr = "R",
 		.raw_type = ND_REDIRECT,
 		.raw_struct_size = sizeof(struct nd_redirect),
+		.addrto_validate = ndp_msg_addrto_validate_link_local,
 	},
 };
 
@@ -418,7 +426,11 @@
 
 	if (len < ndp_msg_type_info(msg_type)->raw_struct_size)
 		return false;
-	return true;
+
+	if (ndp_msg_type_info(msg_type)->addrto_validate)
+		return ndp_msg_type_info(msg_type)->addrto_validate(&msg->addrto);
+	else
+		return true;
 }
 
 static struct ndp_msg *ndp_msg_alloc(void)
```
