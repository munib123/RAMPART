# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3508_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3508_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 146-186 of the vulnerable file.

#define B43_DMA64_DCTL0_FRAMEEND		0x40000000
#define B43_DMA64_DCTL0_FRAMESTART		0x80000000
#define B43_DMA64_DCTL1_BYTECNT		0x00001FFF
#define B43_DMA64_DCTL1_ADDREXT_MASK	0x00030000
#define B43_DMA64_DCTL1_ADDREXT_SHIFT	16

struct b43_dmadesc_generic {
	union {
		struct b43_dmadesc32 dma32;
		struct b43_dmadesc64 dma64;
	} __packed;
} __packed;

/* Misc DMA constants */
#define B43_DMA_RINGMEMSIZE		PAGE_SIZE
#define B43_DMA0_RX_FRAMEOFFSET		30

/* DMA engine tuning knobs */
#define B43_TXRING_SLOTS		256
#define B43_RXRING_SLOTS		64
#define B43_DMA0_RX_BUFFERSIZE		IEEE80211_MAX_FRAME_LEN

/* Pointer poison */
#define B43_DMA_PTR_POISON		((void *)ERR_PTR(-ENOMEM))
#define b43_dma_ptr_is_poisoned(ptr)	(unlikely((ptr) == B43_DMA_PTR_POISON))


struct sk_buff;
struct b43_private;
struct b43_txstatus;

struct b43_dmadesc_meta {
	/* The kernel DMA-able buffer. */
	struct sk_buff *skb;
	/* DMA base bus-address of the descriptor buffer. */
	dma_addr_t dmaaddr;
	/* ieee80211 TX status. Only used once per 802.11 frag. */
	bool is_last_fragment;
};

struct b43_dmaring;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -163,7 +163,7 @@
 /* DMA engine tuning knobs */
 #define B43_TXRING_SLOTS		256
 #define B43_RXRING_SLOTS		64
-#define B43_DMA0_RX_BUFFERSIZE		IEEE80211_MAX_FRAME_LEN
+#define B43_DMA0_RX_BUFFERSIZE		(B43_DMA0_RX_FRAMEOFFSET + IEEE80211_MAX_FRAME_LEN)
 
 /* Pointer poison */
 #define B43_DMA_PTR_POISON		((void *)ERR_PTR(-ENOMEM))
```
