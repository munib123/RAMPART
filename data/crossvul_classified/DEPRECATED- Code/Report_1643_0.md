# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1643_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1643_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 949-989 of the vulnerable file.


	if (!bpf_jit_enable)
		return;

	if (!prog || !prog->len)
		return;

	addrs = kmalloc(prog->len * sizeof(*addrs), GFP_KERNEL);
	if (!addrs)
		return;

	/* Before first pass, make a rough estimation of addrs[]
	 * each bpf instruction is translated to less than 64 bytes
	 */
	for (proglen = 0, i = 0; i < prog->len; i++) {
		proglen += 64;
		addrs[i] = proglen;
	}
	ctx.cleanup_addr = proglen;

	for (pass = 0; pass < 10; pass++) {
		proglen = do_jit(prog, addrs, image, oldproglen, &ctx);
		if (proglen <= 0) {
			image = NULL;
			if (header)
				bpf_jit_binary_free(header);
			goto out;
		}
		if (image) {
			if (proglen != oldproglen) {
				pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
				       proglen, oldproglen);
				goto out;
			}
			break;
		}
		if (proglen == oldproglen) {
			header = bpf_jit_binary_alloc(proglen, &image,
						      1, jit_fill_hole);
			if (!header)
				goto out;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -966,7 +966,12 @@
 	}
 	ctx.cleanup_addr = proglen;
 
-	for (pass = 0; pass < 10; pass++) {
+	/* JITed image shrinks with every pass and the loop iterates
+	 * until the image stops shrinking. Very large bpf programs
+	 * may converge on the last pass. In such case do one more
+	 * pass to emit the final image
+	 */
+	for (pass = 0; pass < 10 || image; pass++) {
 		proglen = do_jit(prog, addrs, image, oldproglen, &ctx);
 		if (proglen <= 0) {
 			image = NULL;
```
