# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5356_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5356_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 2079-2120 of the vulnerable file.

	u16	flush;

	/* Save the IP ID here and check when we get to the transport layer */
	u16	flush_id;

	/* Number of segments aggregated. */
	u16	count;

	/* Start offset for remote checksum offload */
	u16	gro_remcsum_start;

	/* jiffies when first packet was created/queued */
	unsigned long age;

	/* Used in ipv6_gro_receive() and foo-over-udp */
	u16	proto;

	/* This is non-zero if the packet may be of the same flow. */
	u8	same_flow:1;

	/* Used in udp_gro_receive */
	u8	udp_mark:1;

	/* GRO checksum is valid */
	u8	csum_valid:1;

	/* Number of checksums via CHECKSUM_UNNECESSARY */
	u8	csum_cnt:3;

	/* Free the skb? */
	u8	free:2;
#define NAPI_GRO_FREE		  1
#define NAPI_GRO_FREE_STOLEN_HEAD 2

	/* Used in foo-over-udp, set in udp[46]_gro_receive */
	u8	is_ipv6:1;

	/* 7 bit hole */

	/* used to support CHECKSUM_COMPLETE for tunneling protocols */
	__wsum	csum;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2096,8 +2096,8 @@
 	/* This is non-zero if the packet may be of the same flow. */
 	u8	same_flow:1;
 
-	/* Used in udp_gro_receive */
-	u8	udp_mark:1;
+	/* Used in tunnel GRO receive */
+	u8	encap_mark:1;
 
 	/* GRO checksum is valid */
 	u8	csum_valid:1;
```
