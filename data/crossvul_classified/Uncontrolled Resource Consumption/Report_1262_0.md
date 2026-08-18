# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1262_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1262_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 435-476 of the vulnerable file.

	}
	inverts = kmalloc_array(nr_preds, sizeof(*inverts), GFP_KERNEL);
	if (!inverts) {
		parse_error(pe, -ENOMEM, 0);
		goto out_free;
	}

	top = op_stack;
	prog = prog_stack;
	*top = 0;

	/* First pass */
	while (*ptr) {						/* #1 */
		const char *next = ptr++;

		if (isspace(*next))
			continue;

		switch (*next) {
		case '(':					/* #2 */
			if (top - op_stack > nr_parens)
				return ERR_PTR(-EINVAL);
			*(++top) = invert;
			continue;
		case '!':					/* #3 */
			if (!is_not(next))
				break;
			invert = !invert;
			continue;
		}

		if (N >= nr_preds) {
			parse_error(pe, FILT_ERR_TOO_MANY_PREDS, next - str);
			goto out_free;
		}

		inverts[N] = invert;				/* #4 */
		prog[N].target = N-1;

		len = parse_pred(next, data, ptr - str, pe, &prog[N].pred);
		if (len < 0) {
			ret = len;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -452,8 +452,10 @@
 
 		switch (*next) {
 		case '(':					/* #2 */
-			if (top - op_stack > nr_parens)
-				return ERR_PTR(-EINVAL);
+			if (top - op_stack > nr_parens) {
+				ret = -EINVAL;
+				goto out_free;
+			}
 			*(++top) = invert;
 			continue;
 		case '!':					/* #3 */
```
