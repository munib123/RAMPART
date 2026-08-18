# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3635_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3635_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 512-552 of the vulnerable file.

		offset1 += size;
	}

	if (len == offset1)
		return 0;

	while (count--) {
		struct page *page[MAX_SKB_FRAGS];
		int num_pages;
		unsigned long base;
		unsigned long truesize;

		len = from->iov_len - offset;
		if (!len) {
			offset = 0;
			++from;
			continue;
		}
		base = (unsigned long)from->iov_base + offset;
		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
		num_pages = get_user_pages_fast(base, size, 0, &page[i]);
		if ((num_pages != size) ||
		    (num_pages > MAX_SKB_FRAGS - skb_shinfo(skb)->nr_frags)) {
			for (i = 0; i < num_pages; i++)
				put_page(page[i]);
			return -EFAULT;
		}
		truesize = size * PAGE_SIZE;
		skb->data_len += len;
		skb->len += len;
		skb->truesize += truesize;
		atomic_add(truesize, &skb->sk->sk_wmem_alloc);
		while (len) {
			int off = base & ~PAGE_MASK;
			int size = min_t(int, len, PAGE_SIZE - off);
			__skb_fill_page_desc(skb, i, page[i], off, size);
			skb_shinfo(skb)->nr_frags++;
			/* increase sk_wmem_alloc */
			base += size;
			len -= size;
			i++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -529,9 +529,10 @@
 		}
 		base = (unsigned long)from->iov_base + offset;
 		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
+		if (i + size > MAX_SKB_FRAGS)
+			return -EMSGSIZE;
 		num_pages = get_user_pages_fast(base, size, 0, &page[i]);
-		if ((num_pages != size) ||
-		    (num_pages > MAX_SKB_FRAGS - skb_shinfo(skb)->nr_frags)) {
+		if (num_pages != size) {
 			for (i = 0; i < num_pages; i++)
 				put_page(page[i]);
 			return -EFAULT;
@@ -651,7 +652,7 @@
 	int err;
 	struct virtio_net_hdr vnet_hdr = { 0 };
 	int vnet_hdr_len = 0;
-	int copylen;
+	int copylen = 0;
 	bool zerocopy = false;
 
 	if (q->flags & IFF_VNET_HDR) {
@@ -680,15 +681,31 @@
 	if (unlikely(len < ETH_HLEN))
 		goto err;
 
+	err = -EMSGSIZE;
+	if (unlikely(count > UIO_MAXIOV))
+		goto err;
+
 	if (m && m->msg_control && sock_flag(&q->sk, SOCK_ZEROCOPY))
 		zerocopy = true;
 
 	if (zerocopy) {
+		/* Userspace may produce vectors with count greater than
+		 * MAX_SKB_FRAGS, so we need to linearize parts of the skb
+		 * to let the rest of data to be fit in the frags.
+		 */
+		if (count > MAX_SKB_FRAGS) {
+			copylen = iov_length(iv, count - MAX_SKB_FRAGS);
+			if (copylen < vnet_hdr_len)
+				copylen = 0;
+			else
+				copylen -= vnet_hdr_len;
+		}
 		/* There are 256 bytes to be copied in skb, so there is enough
 		 * room for skb expand head in case it is used.
 		 * The rest buffer is mapped from userspace.
 		 */
-		copylen = vnet_hdr.hdr_len;
+		if (copylen < vnet_hdr.hdr_len)
+			copylen = vnet_hdr.hdr_len;
 		if (!copylen)
 			copylen = GOODCOPY_LEN;
 	} else
```
