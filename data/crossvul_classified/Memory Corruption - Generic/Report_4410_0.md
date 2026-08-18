# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4410_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4410_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1959-1999 of the vulnerable file.

input_csi_dispatch_sgr_colon(struct input_ctx *ictx, u_int i)
{
	struct grid_cell	*gc = &ictx->cell.cell;
	char			*s = ictx->param_list[i].str, *copy, *ptr, *out;
	int			 p[8];
	u_int			 n;
	const char		*errstr;

	for (n = 0; n < nitems(p); n++)
		p[n] = -1;
	n = 0;

	ptr = copy = xstrdup(s);
	while ((out = strsep(&ptr, ":")) != NULL) {
		if (*out != '\0') {
			p[n++] = strtonum(out, 0, INT_MAX, &errstr);
			if (errstr != NULL || n == nitems(p)) {
				free(copy);
				return;
			}
		} else
			n++;
		log_debug("%s: %u = %d", __func__, n - 1, p[n - 1]);
	}
	free(copy);

	if (n == 0)
		return;
	if (p[0] == 4) {
		if (n != 2)
			return;
		switch (p[1]) {
		case 0:
			gc->attr &= ~GRID_ATTR_ALL_UNDERSCORE;
			break;
		case 1:
			gc->attr &= ~GRID_ATTR_ALL_UNDERSCORE;
			gc->attr |= GRID_ATTR_UNDERSCORE;
			break;
		case 2:
			gc->attr &= ~GRID_ATTR_ALL_UNDERSCORE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1976,8 +1976,13 @@
 				free(copy);
 				return;
 			}
-		} else
+		} else {
 			n++;
+			if (n == nitems(p)) {
+				free(copy);
+				return;
+			}
+		}
 		log_debug("%s: %u = %d", __func__, n - 1, p[n - 1]);
 	}
 	free(copy);
```
