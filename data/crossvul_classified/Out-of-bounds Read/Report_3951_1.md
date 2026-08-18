# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3951_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3951_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 172-212 of the vulnerable file.

#define ORDER_TYPE_BITMAP_COMPRESSED_V3 0x08

/* Alternate Secondary Drawing Orders */
#define ORDER_TYPE_SWITCH_SURFACE 0x00
#define ORDER_TYPE_CREATE_OFFSCREEN_BITMAP 0x01
#define ORDER_TYPE_STREAM_BITMAP_FIRST 0x02
#define ORDER_TYPE_STREAM_BITMAP_NEXT 0x03
#define ORDER_TYPE_CREATE_NINE_GRID_BITMAP 0x04
#define ORDER_TYPE_GDIPLUS_FIRST 0x05
#define ORDER_TYPE_GDIPLUS_NEXT 0x06
#define ORDER_TYPE_GDIPLUS_END 0x07
#define ORDER_TYPE_GDIPLUS_CACHE_FIRST 0x08
#define ORDER_TYPE_GDIPLUS_CACHE_NEXT 0x09
#define ORDER_TYPE_GDIPLUS_CACHE_END 0x0A
#define ORDER_TYPE_WINDOW 0x0B
#define ORDER_TYPE_COMPDESK_FIRST 0x0C
#define ORDER_TYPE_FRAME_MARKER 0x0D

#define CG_GLYPH_UNICODE_PRESENT 0x0010

FREERDP_LOCAL extern const BYTE PRIMARY_DRAWING_ORDER_FIELD_BYTES[];

FREERDP_LOCAL BOOL update_recv_order(rdpUpdate* update, wStream* s);

FREERDP_LOCAL BOOL update_write_field_flags(wStream* s, UINT32 fieldFlags, BYTE flags,
                                            BYTE fieldBytes);

FREERDP_LOCAL BOOL update_write_bounds(wStream* s, ORDER_INFO* orderInfo);

FREERDP_LOCAL int update_approximate_dstblt_order(ORDER_INFO* orderInfo,
                                                  const DSTBLT_ORDER* dstblt);
FREERDP_LOCAL BOOL update_write_dstblt_order(wStream* s, ORDER_INFO* orderInfo,
                                             const DSTBLT_ORDER* dstblt);

FREERDP_LOCAL int update_approximate_patblt_order(ORDER_INFO* orderInfo, PATBLT_ORDER* patblt);
FREERDP_LOCAL BOOL update_write_patblt_order(wStream* s, ORDER_INFO* orderInfo,
                                             PATBLT_ORDER* patblt);

FREERDP_LOCAL int update_approximate_scrblt_order(ORDER_INFO* orderInfo,
                                                  const SCRBLT_ORDER* scrblt);
FREERDP_LOCAL BOOL update_write_scrblt_order(wStream* s, ORDER_INFO* orderInfo,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,7 +189,7 @@
 
 #define CG_GLYPH_UNICODE_PRESENT 0x0010
 
-FREERDP_LOCAL extern const BYTE PRIMARY_DRAWING_ORDER_FIELD_BYTES[];
+FREERDP_LOCAL BYTE get_primary_drawing_order_field_bytes(UINT32 orderType, BOOL* pValid);
 
 FREERDP_LOCAL BOOL update_recv_order(rdpUpdate* update, wStream* s);
 
```
