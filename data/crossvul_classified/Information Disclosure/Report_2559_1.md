# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2559_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2559_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 58-100 of the vulnerable file.

 * Number of Xen pages per segment
 */
#define XEN_PAGES_PER_SEGMENT   (PAGE_SIZE / XEN_PAGE_SIZE)

#define XEN_PAGES_PER_INDIRECT_FRAME \
	(XEN_PAGE_SIZE/sizeof(struct blkif_request_segment))
#define SEGS_PER_INDIRECT_FRAME	\
	(XEN_PAGES_PER_INDIRECT_FRAME / XEN_PAGES_PER_SEGMENT)

#define MAX_INDIRECT_PAGES \
	((MAX_INDIRECT_SEGMENTS + SEGS_PER_INDIRECT_FRAME - 1)/SEGS_PER_INDIRECT_FRAME)
#define INDIRECT_PAGES(_segs) DIV_ROUND_UP(_segs, XEN_PAGES_PER_INDIRECT_FRAME)

/* Not a real protocol.  Used to generate ring structs which contain
 * the elements common to all protocols only.  This way we get a
 * compiler-checkable way to use common struct elements, so we can
 * avoid using switch(protocol) in a number of places.  */
struct blkif_common_request {
	char dummy;
};
struct blkif_common_response {
	char dummy;
};

struct blkif_x86_32_request_rw {
	uint8_t        nr_segments;  /* number of segments                   */
	blkif_vdev_t   handle;       /* only for read/write requests         */
	uint64_t       id;           /* private guest value, echoed in resp  */
	blkif_sector_t sector_number;/* start sector idx on disk (r/w only)  */
	struct blkif_request_segment seg[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} __attribute__((__packed__));

struct blkif_x86_32_request_discard {
	uint8_t        flag;         /* BLKIF_DISCARD_SECURE or zero         */
	blkif_vdev_t   _pad1;        /* was "handle" for read/write requests */
	uint64_t       id;           /* private guest value, echoed in resp  */
	blkif_sector_t sector_number;/* start sector idx on disk (r/w only)  */
	uint64_t       nr_sectors;
} __attribute__((__packed__));

struct blkif_x86_32_request_other {
	uint8_t        _pad1;
	blkif_vdev_t   _pad2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,9 +75,8 @@
 struct blkif_common_request {
 	char dummy;
 };
-struct blkif_common_response {
-	char dummy;
-};
+
+/* i386 protocol version */
 
 struct blkif_x86_32_request_rw {
 	uint8_t        nr_segments;  /* number of segments                   */
@@ -129,14 +128,6 @@
 	} u;
 } __attribute__((__packed__));
 
-/* i386 protocol version */
-#pragma pack(push, 4)
-struct blkif_x86_32_response {
-	uint64_t        id;              /* copied from request */
-	uint8_t         operation;       /* copied from request */
-	int16_t         status;          /* BLKIF_RSP_???       */
-};
-#pragma pack(pop)
 /* x86_64 protocol version */
 
 struct blkif_x86_64_request_rw {
@@ -193,18 +184,12 @@
 	} u;
 } __attribute__((__packed__));
 
-struct blkif_x86_64_response {
-	uint64_t       __attribute__((__aligned__(8))) id;
-	uint8_t         operation;       /* copied from request */
-	int16_t         status;          /* BLKIF_RSP_???       */
-};
-
 DEFINE_RING_TYPES(blkif_common, struct blkif_common_request,
-		  struct blkif_common_response);
+		  struct blkif_response);
 DEFINE_RING_TYPES(blkif_x86_32, struct blkif_x86_32_request,
-		  struct blkif_x86_32_response);
+		  struct blkif_response __packed);
 DEFINE_RING_TYPES(blkif_x86_64, struct blkif_x86_64_request,
-		  struct blkif_x86_64_response);
+		  struct blkif_response);
 
 union blkif_back_rings {
 	struct blkif_back_ring        native;
```
