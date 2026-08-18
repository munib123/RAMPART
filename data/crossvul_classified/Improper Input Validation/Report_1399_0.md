# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1399_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1399_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

	{BGP_ATTR_AS_PATH, "AS_PATH"},
	{BGP_ATTR_NEXT_HOP, "NEXT_HOP"},
	{BGP_ATTR_MULTI_EXIT_DISC, "MULTI_EXIT_DISC"},
	{BGP_ATTR_LOCAL_PREF, "LOCAL_PREF"},
	{BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE"},
	{BGP_ATTR_AGGREGATOR, "AGGREGATOR"},
	{BGP_ATTR_COMMUNITIES, "COMMUNITY"},
	{BGP_ATTR_ORIGINATOR_ID, "ORIGINATOR_ID"},
	{BGP_ATTR_CLUSTER_LIST, "CLUSTER_LIST"},
	{BGP_ATTR_DPA, "DPA"},
	{BGP_ATTR_ADVERTISER, "ADVERTISER"},
	{BGP_ATTR_RCID_PATH, "RCID_PATH"},
	{BGP_ATTR_MP_REACH_NLRI, "MP_REACH_NLRI"},
	{BGP_ATTR_MP_UNREACH_NLRI, "MP_UNREACH_NLRI"},
	{BGP_ATTR_EXT_COMMUNITIES, "EXT_COMMUNITIES"},
	{BGP_ATTR_AS4_PATH, "AS4_PATH"},
	{BGP_ATTR_AS4_AGGREGATOR, "AS4_AGGREGATOR"},
	{BGP_ATTR_AS_PATHLIMIT, "AS_PATHLIMIT"},
	{BGP_ATTR_PMSI_TUNNEL, "PMSI_TUNNEL_ATTRIBUTE"},
	{BGP_ATTR_ENCAP, "ENCAP"},
#if ENABLE_BGP_VNC
	{BGP_ATTR_VNC, "VNC"},
#endif
	{BGP_ATTR_LARGE_COMMUNITIES, "LARGE_COMMUNITY"},
	{BGP_ATTR_PREFIX_SID, "PREFIX_SID"},
	{0}};

static const struct message attr_flag_str[] = {
	{BGP_ATTR_FLAG_OPTIONAL, "Optional"},
	{BGP_ATTR_FLAG_TRANS, "Transitive"},
	{BGP_ATTR_FLAG_PARTIAL, "Partial"},
	/* bgp_attr_flags_diagnose() relies on this bit being last in
	   this list */
	{BGP_ATTR_FLAG_EXTLEN, "Extended Length"},
	{0}};

static struct hash *cluster_hash;

static void *cluster_hash_alloc(void *p)
{
	const struct cluster_list *val = (const struct cluster_list *)p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 	{BGP_ATTR_AS_PATHLIMIT, "AS_PATHLIMIT"},
 	{BGP_ATTR_PMSI_TUNNEL, "PMSI_TUNNEL_ATTRIBUTE"},
 	{BGP_ATTR_ENCAP, "ENCAP"},
-#if ENABLE_BGP_VNC
+#if ENABLE_BGP_VNC_ATTR
 	{BGP_ATTR_VNC, "VNC"},
 #endif
 	{BGP_ATTR_LARGE_COMMUNITIES, "LARGE_COMMUNITY"},
@@ -2593,7 +2593,7 @@
 		case BGP_ATTR_EXT_COMMUNITIES:
 			ret = bgp_attr_ext_communities(&attr_args);
 			break;
-#if ENABLE_BGP_VNC
+#if ENABLE_BGP_VNC_ATTR
 		case BGP_ATTR_VNC:
 #endif
 		case BGP_ATTR_ENCAP:
@@ -2946,7 +2946,7 @@
 		attrhdrlen = 1 + 1;   /* subTLV T + L */
 		break;
 
-#if ENABLE_BGP_VNC
+#if ENABLE_BGP_VNC_ATTR
 	case BGP_ATTR_VNC:
 		attrname = "VNC";
 		subtlvs = attr->vnc_subtlvs;
@@ -3433,7 +3433,7 @@
 		/* Tunnel Encap attribute */
 		bgp_packet_mpattr_tea(bgp, peer, s, attr, BGP_ATTR_ENCAP);
 
-#if ENABLE_BGP_VNC
+#if ENABLE_BGP_VNC_ATTR
 		/* VNC attribute */
 		bgp_packet_mpattr_tea(bgp, peer, s, attr, BGP_ATTR_VNC);
 #endif
```
