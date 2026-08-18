# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3316_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3316_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1119-1159 of the vulnerable file.

	.write = port_fops_write,
	.splice_write = port_fops_splice_write,
	.poll  = port_fops_poll,
	.release = port_fops_release,
	.fasync = port_fops_fasync,
	.llseek = no_llseek,
};

/*
 * The put_chars() callback is pretty straightforward.
 *
 * We turn the characters into a scatter-gather list, add it to the
 * output queue and then kick the Host.  Then we sit here waiting for
 * it to finish: inefficient in theory, but in practice
 * implementations will do it immediately (lguest's Launcher does).
 */
static int put_chars(u32 vtermno, const char *buf, int count)
{
	struct port *port;
	struct scatterlist sg[1];

	if (unlikely(early_put_chars))
		return early_put_chars(vtermno, buf, count);

	port = find_port_by_vtermno(vtermno);
	if (!port)
		return -EPIPE;

	sg_init_one(sg, buf, count);
	return __send_to_port(port, sg, 1, count, (void *)buf, false);
}

/*
 * get_chars() is the callback from the hvc_console infrastructure
 * when an interrupt is received.
 *
 * We call out to fill_readbuf that gets us the required data from the
 * buffers that are queued up.
 */
static int get_chars(u32 vtermno, char *buf, int count)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1136,6 +1136,8 @@
 {
 	struct port *port;
 	struct scatterlist sg[1];
+	void *data;
+	int ret;
 
 	if (unlikely(early_put_chars))
 		return early_put_chars(vtermno, buf, count);
@@ -1144,8 +1146,14 @@
 	if (!port)
 		return -EPIPE;
 
-	sg_init_one(sg, buf, count);
-	return __send_to_port(port, sg, 1, count, (void *)buf, false);
+	data = kmemdup(buf, count, GFP_ATOMIC);
+	if (!data)
+		return -ENOMEM;
+
+	sg_init_one(sg, data, count);
+	ret = __send_to_port(port, sg, 1, count, data, false);
+	kfree(data);
+	return ret;
 }
 
 /*
```
