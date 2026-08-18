# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 734-774 of the vulnerable file.

#define RNS_UD_CS_UNUSED			0x0010
#define RNS_UD_CS_VALID_CONNECTION_TYPE		0x0020
#define RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU	0x0040
#define RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT	0x0080
#define RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL	0x0100
#define RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE	0x0200
#define RNS_UD_CS_SUPPORT_HEARTBEAT_PDU		0x0400

/* [MS-RDPBCGR] 2.2.7.1.1 */
#define OSMAJORTYPE_WINDOWS	0x0001
#define OSMINORTYPE_WINDOWSNT	0x0003
#define TS_CAPS_PROTOCOLVERSION	0x0200

/* extraFlags, [MS-RDPBCGR] 2.2.7.1.1 */
#define FASTPATH_OUTPUT_SUPPORTED	0x0001
#define LONG_CREDENTIALS_SUPPORTED	0x0004
#define AUTORECONNECT_SUPPORTED		0x0008
#define ENC_SALTED_CHECKSUM		0x0010
#define NO_BITMAP_COMPRESSION_HDR	0x0400

/* orderFlags, [MS-RDPBCGR] 2.2.7.1.3 */
#define NEGOTIATEORDERSUPPORT	0x0002
#define ZEROBOUNDSDELTASSUPPORT 0x0008
#define COLORINDEXSUPPORT	0x0020
#define SOLIDPATTERNBRUSHONLY	0x0040
#define ORDERFLAGS_EXTRA_FLAGS	0x0080

/* orderSupport index, [MS-RDPBCGR] 2.2.7.1.3 */
#define TS_NEG_DSTBLT_INDEX		0x00
#define TS_NEG_PATBLT_INDEX		0x01
#define TS_NEG_SCRBLT_INDEX		0x02
#define TS_NEG_MEMBLT_INDEX		0x03
#define TS_NEG_MEM3BLT_INDEX		0x04
#define TS_NEG_DRAWNINEGRID_INDEX	0x07
#define TS_NEG_LINETO_INDEX		0x08
#define TS_NEG_MULTI_DRAWNINEGRID_INDEX 0x09
#define TS_NEG_SAVEBITMAP_INDEX		0x0B
#define TS_NEG_MULTIDSTBLT_INDEX	0x0F
#define TS_NEG_MULTIPATBLT_INDEX	0x10
#define TS_NEG_MULTISCRBLT_INDEX	0x11
#define TS_NEG_MULTIOPAQUERECT_INDEX	0x12
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -751,6 +751,9 @@
 #define ENC_SALTED_CHECKSUM		0x0010
 #define NO_BITMAP_COMPRESSION_HDR	0x0400
 
+/* [MS-RDPBCGR], TS_BITMAP_DATA, flags */
+#define BITMAP_COMPRESSION              0x0001
+
 /* orderFlags, [MS-RDPBCGR] 2.2.7.1.3 */
 #define NEGOTIATEORDERSUPPORT	0x0002
 #define ZEROBOUNDSDELTASSUPPORT 0x0008
```
