# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5738_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5738_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 252-292 of the vulnerable file.


	/*
	 * Issue the synchronous I/O from a different thread
	 * to avoid generic_make_request recursion.
	 */
	INIT_WORK_ONSTACK(&req.work, do_metadata);
	queue_work(ps->metadata_wq, &req.work);
	flush_workqueue(ps->metadata_wq);

	return req.result;
}

/*
 * Convert a metadata area index to a chunk index.
 */
static chunk_t area_location(struct pstore *ps, chunk_t area)
{
	return NUM_SNAPSHOT_HDR_CHUNKS + ((ps->exceptions_per_area + 1) * area);
}

/*
 * Read or write a metadata area.  Remembering to skip the first
 * chunk which holds the header.
 */
static int area_io(struct pstore *ps, int rw)
{
	int r;
	chunk_t chunk;

	chunk = area_location(ps, ps->current_area);

	r = chunk_io(ps, ps->area, chunk, rw, 0);
	if (r)
		return r;

	return 0;
}

static void zero_memory_area(struct pstore *ps)
{
	memset(ps->area, 0, ps->store->chunk_size << SECTOR_SHIFT);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -269,6 +269,14 @@
 	return NUM_SNAPSHOT_HDR_CHUNKS + ((ps->exceptions_per_area + 1) * area);
 }
 
+static void skip_metadata(struct pstore *ps)
+{
+	uint32_t stride = ps->exceptions_per_area + 1;
+	chunk_t next_free = ps->next_free;
+	if (sector_div(next_free, stride) == NUM_SNAPSHOT_HDR_CHUNKS)
+		ps->next_free++;
+}
+
 /*
  * Read or write a metadata area.  Remembering to skip the first
  * chunk which holds the header.
@@ -502,6 +510,8 @@
 
 	ps->current_area--;
 
+	skip_metadata(ps);
+
 	return 0;
 }
 
@@ -616,8 +626,6 @@
 					struct dm_exception *e)
 {
 	struct pstore *ps = get_info(store);
-	uint32_t stride;
-	chunk_t next_free;
 	sector_t size = get_dev_size(dm_snap_cow(store->snap)->bdev);
 
 	/* Is there enough room ? */
@@ -630,10 +638,8 @@
 	 * Move onto the next free pending, making sure to take
 	 * into account the location of the metadata chunks.
 	 */
-	stride = (ps->exceptions_per_area + 1);
-	next_free = ++ps->next_free;
-	if (sector_div(next_free, stride) == 1)
-		ps->next_free++;
+	ps->next_free++;
+	skip_metadata(ps);
 
 	atomic_inc(&ps->pending_count);
 	return 0;
```
