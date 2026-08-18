# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1026_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1026_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

#define OPT_ENDOFOPT	0	/* end of options */
#define OPT_COMMENT	1	/* comment string */

/*
 * Option header.
 */
struct option_header {
	u_short		option_code;
	u_short		option_length;
};

/*
 * Structures for the part of each block type following the common
 * part.
 */

/*
 * Section Header Block.
 */
#define BT_SHB			0x0A0D0D0A

struct section_header_block {
	bpf_u_int32	byte_order_magic;
	u_short		major_version;
	u_short		minor_version;
	uint64_t	section_length;
	/* followed by options and trailer */
};

/*
 * Byte-order magic value.
 */
#define BYTE_ORDER_MAGIC	0x1A2B3C4D

/*
 * Current version number.  If major_version isn't PCAP_NG_VERSION_MAJOR,
 * that means that this code can't read the file.
 */
#define PCAP_NG_VERSION_MAJOR	1
#define PCAP_NG_VERSION_MINOR	0

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,7 @@
  * Section Header Block.
  */
 #define BT_SHB			0x0A0D0D0A
-
+#define BT_SHB_INSANE_MAX       1024*1024*1  /* 1MB should be enough */
 struct section_header_block {
 	bpf_u_int32	byte_order_magic;
 	u_short		major_version;
@@ -266,7 +266,7 @@
 			if (amt_read == 0 && !fail_on_eof)
 				return (0);	/* EOF */
 			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
-			    "truncated dump file; tried to read %" PRIsize " bytes, only got %" PRIsize,
+			    "truncated pcapng dump file; tried to read %" PRIsize " bytes, only got %" PRIsize,
 			    bytes_to_read, amt_read);
 		}
 		return (-1);
@@ -856,25 +856,19 @@
 	/*
 	 * Check the sanity of the total length.
 	 */
-	if (total_length < sizeof(*bhdrp) + sizeof(*shbp) + sizeof(struct block_trailer)) {
+	if (total_length < sizeof(*bhdrp) + sizeof(*shbp) + sizeof(struct block_trailer) ||
+            (total_length > BT_SHB_INSANE_MAX)) {
 		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
-		    "Section Header Block in pcapng dump file has a length of %u < %" PRIsize,
-		    total_length,
-		    sizeof(*bhdrp) + sizeof(*shbp) + sizeof(struct block_trailer));
+		    "Section Header Block in pcapng dump file has invalid length %" PRIsize " < _%lu_ < %lu (BT_SHB_INSANE_MAX)",
+                              sizeof(*bhdrp) + sizeof(*shbp) + sizeof(struct block_trailer),
+                              total_length,
+                              BT_SHB_INSANE_MAX);
+
 		*err = 1;
 		return (NULL);
 	}
 
-	/*
-	 * Make sure it's not too big.
-	 */
-	if (total_length > INITIAL_MAX_BLOCKSIZE) {
-		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
-		    "pcapng block size %u > maximum %u",
-		    total_length, INITIAL_MAX_BLOCKSIZE);
-		*err = 1;
-		return (NULL);
-	}
+
 
 	/*
 	 * OK, this is a good pcapng file.
```
