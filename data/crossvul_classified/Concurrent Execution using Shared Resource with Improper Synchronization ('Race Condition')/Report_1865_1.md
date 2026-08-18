# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1865_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1865_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 412-452 of the vulnerable file.

			*last_tag = real_tag;
	} else {
		BUG_ON(tag >= tags->nr_reserved_tags);
		bt_clear_tag(&tags->breserved_tags, tag);
	}
}

static void bt_for_each(struct blk_mq_hw_ctx *hctx,
		struct blk_mq_bitmap_tags *bt, unsigned int off,
		busy_iter_fn *fn, void *data, bool reserved)
{
	struct request *rq;
	int bit, i;

	for (i = 0; i < bt->map_nr; i++) {
		struct blk_align_bitmap *bm = &bt->map[i];

		for (bit = find_first_bit(&bm->word, bm->depth);
		     bit < bm->depth;
		     bit = find_next_bit(&bm->word, bm->depth, bit + 1)) {
		     	rq = blk_mq_tag_to_rq(hctx->tags, off + bit);
			if (rq->q == hctx->queue)
				fn(hctx, rq, data, reserved);
		}

		off += (1 << bt->bits_per_word);
	}
}

static void bt_tags_for_each(struct blk_mq_tags *tags,
		struct blk_mq_bitmap_tags *bt, unsigned int off,
		busy_tag_iter_fn *fn, void *data, bool reserved)
{
	struct request *rq;
	int bit, i;

	if (!tags->rqs)
		return;
	for (i = 0; i < bt->map_nr; i++) {
		struct blk_align_bitmap *bm = &bt->map[i];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -429,7 +429,7 @@
 		for (bit = find_first_bit(&bm->word, bm->depth);
 		     bit < bm->depth;
 		     bit = find_next_bit(&bm->word, bm->depth, bit + 1)) {
-		     	rq = blk_mq_tag_to_rq(hctx->tags, off + bit);
+			rq = hctx->tags->rqs[off + bit];
 			if (rq->q == hctx->queue)
 				fn(hctx, rq, data, reserved);
 		}
@@ -453,7 +453,7 @@
 		for (bit = find_first_bit(&bm->word, bm->depth);
 		     bit < bm->depth;
 		     bit = find_next_bit(&bm->word, bm->depth, bit + 1)) {
-			rq = blk_mq_tag_to_rq(tags, off + bit);
+			rq = tags->rqs[off + bit];
 			fn(rq, data, reserved);
 		}
 
```
