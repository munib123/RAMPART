# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3527_3
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3527_3`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 174-214 of the vulnerable file.

extern int csum_partial_copy_to_xdr(struct xdr_buf *, struct sk_buff *);
extern ssize_t xdr_partial_copy_from_skb(struct xdr_buf *, unsigned int,
		struct xdr_skb_reader *, xdr_skb_read_actor);

extern int xdr_encode_word(struct xdr_buf *, unsigned int, u32);
extern int xdr_decode_word(struct xdr_buf *, unsigned int, u32 *);

struct xdr_array2_desc;
typedef int (*xdr_xcode_elem_t)(struct xdr_array2_desc *desc, void *elem);
struct xdr_array2_desc {
	unsigned int elem_size;
	unsigned int array_len;
	unsigned int array_maxlen;
	xdr_xcode_elem_t xcode;
};

extern int xdr_decode_array2(struct xdr_buf *buf, unsigned int base,
			     struct xdr_array2_desc *desc);
extern int xdr_encode_array2(struct xdr_buf *buf, unsigned int base,
			     struct xdr_array2_desc *desc);

/*
 * Provide some simple tools for XDR buffer overflow-checking etc.
 */
struct xdr_stream {
	__be32 *p;		/* start of available buffer */
	struct xdr_buf *buf;	/* XDR buffer to read/write */

	__be32 *end;		/* end of available buffer space */
	struct kvec *iov;	/* pointer to the current kvec */
	struct kvec scratch;	/* Scratch buffer */
	struct page **page_ptr;	/* pointer to the current page */
};

/*
 * These are the xdr_stream style generic XDR encode and decode functions.
 */
typedef void	(*kxdreproc_t)(void *rqstp, struct xdr_stream *xdr, void *obj);
typedef int	(*kxdrdproc_t)(void *rqstp, struct xdr_stream *xdr, void *obj);

extern void xdr_init_encode(struct xdr_stream *xdr, struct xdr_buf *buf, __be32 *p);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,6 +191,8 @@
 			     struct xdr_array2_desc *desc);
 extern int xdr_encode_array2(struct xdr_buf *buf, unsigned int base,
 			     struct xdr_array2_desc *desc);
+extern void _copy_from_pages(char *p, struct page **pages, size_t pgbase,
+			     size_t len);
 
 /*
  * Provide some simple tools for XDR buffer overflow-checking etc.
```
