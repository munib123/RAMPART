# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5361_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5361_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 284-324 of the vulnerable file.

				if (nlsize != NULL)
					*nlsize = 2;
				return (len+2);
			}
			/* FALL THROUGH */
		case '\n':
			if (nlsize != NULL)
				*nlsize = 1;
			return (len+1);
		default:
			b++;
			len++;
			break;
		}
	}
	if (nlsize != NULL)
		*nlsize = 0;
	return (avail);
}

static ssize_t
next_line(struct archive_read *a,
    const char **b, ssize_t *avail, ssize_t *ravail, ssize_t *nl)
{
	ssize_t len;
	int quit;
	
	quit = 0;
	if (*avail == 0) {
		*nl = 0;
		len = 0;
	} else
		len = get_line_size(*b, *avail, nl);
	/*
	 * Read bytes more while it does not reach the end of line.
	 */
	while (*nl == 0 && len == *avail && !quit) {
		ssize_t diff = *ravail - *avail;
		size_t nbytes_req = (*ravail+1023) & ~1023U;
		ssize_t tested;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -301,6 +301,15 @@
 	return (avail);
 }
 
+/*
+ *  <---------------- ravail --------------------->
+ *  <-- diff ------> <---  avail ----------------->
+ *                   <---- len ----------->
+ * | Previous lines | line being parsed  nl extra |
+ *                  ^
+ *                  b
+ *
+ */
 static ssize_t
 next_line(struct archive_read *a,
     const char **b, ssize_t *avail, ssize_t *ravail, ssize_t *nl)
@@ -339,7 +348,7 @@
 		*b += diff;
 		*avail -= diff;
 		tested = len;/* Skip some bytes we already determinated. */
-		len = get_line_size(*b, *avail, nl);
+		len = get_line_size(*b + len, *avail - len, nl);
 		if (len >= 0)
 			len += tested;
 	}
```
