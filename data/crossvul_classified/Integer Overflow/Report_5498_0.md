# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5498_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5498_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1640-1681 of the vulnerable file.

 * Returns 0 on success and < 0 on failure.
 */
int ring_buffer_resize(struct ring_buffer *buffer, unsigned long size,
			int cpu_id)
{
	struct ring_buffer_per_cpu *cpu_buffer;
	unsigned long nr_pages;
	int cpu, err = 0;

	/*
	 * Always succeed at resizing a non-existent buffer:
	 */
	if (!buffer)
		return size;

	/* Make sure the requested buffer exists */
	if (cpu_id != RING_BUFFER_ALL_CPUS &&
	    !cpumask_test_cpu(cpu_id, buffer->cpumask))
		return size;

	size = DIV_ROUND_UP(size, BUF_PAGE_SIZE);
	size *= BUF_PAGE_SIZE;

	/* we need a minimum of two pages */
	if (size < BUF_PAGE_SIZE * 2)
		size = BUF_PAGE_SIZE * 2;

	nr_pages = DIV_ROUND_UP(size, BUF_PAGE_SIZE);

	/*
	 * Don't succeed if resizing is disabled, as a reader might be
	 * manipulating the ring buffer and is expecting a sane state while
	 * this is true.
	 */
	if (atomic_read(&buffer->resize_disabled))
		return -EBUSY;

	/* prevent another thread from changing buffer sizes */
	mutex_lock(&buffer->mutex);

	if (cpu_id == RING_BUFFER_ALL_CPUS) {
		/* calculate the pages to update */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1657,14 +1657,13 @@
 	    !cpumask_test_cpu(cpu_id, buffer->cpumask))
 		return size;
 
-	size = DIV_ROUND_UP(size, BUF_PAGE_SIZE);
-	size *= BUF_PAGE_SIZE;
+	nr_pages = DIV_ROUND_UP(size, BUF_PAGE_SIZE);
 
 	/* we need a minimum of two pages */
-	if (size < BUF_PAGE_SIZE * 2)
-		size = BUF_PAGE_SIZE * 2;
-
-	nr_pages = DIV_ROUND_UP(size, BUF_PAGE_SIZE);
+	if (nr_pages < 2)
+		nr_pages = 2;
+
+	size = nr_pages * BUF_PAGE_SIZE;
 
 	/*
 	 * Don't succeed if resizing is disabled, as a reader might be
```
