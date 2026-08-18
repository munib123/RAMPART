# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 296_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `296_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 282-322 of the vulnerable file.


	memcpy(pkt->ref, line, len);
	pkt->ref[len] = '\0';

	*out = (git_pkt *)pkt;
	return 0;
}

static int ng_pkt(git_pkt **out, const char *line, size_t len)
{
	git_pkt_ng *pkt;
	const char *ptr;
	size_t alloclen;

	pkt = git__malloc(sizeof(*pkt));
	GITERR_CHECK_ALLOC(pkt);

	pkt->ref = NULL;
	pkt->type = GIT_PKT_NG;

	line += 3; /* skip "ng " */
	if (!(ptr = strchr(line, ' ')))
		goto out_err;
	len = ptr - line;

	GITERR_CHECK_ALLOC_ADD(&alloclen, len, 1);
	pkt->ref = git__malloc(alloclen);
	GITERR_CHECK_ALLOC(pkt->ref);

	memcpy(pkt->ref, line, len);
	pkt->ref[len] = '\0';

	line = ptr + 1;
	if (!(ptr = strchr(line, '\n')))
		goto out_err;
	len = ptr - line;

	GITERR_CHECK_ALLOC_ADD(&alloclen, len, 1);
	pkt->msg = git__malloc(alloclen);
	GITERR_CHECK_ALLOC(pkt->msg);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -299,8 +299,11 @@
 	pkt->ref = NULL;
 	pkt->type = GIT_PKT_NG;
 
+	if (len < 3)
+		goto out_err;
 	line += 3; /* skip "ng " */
-	if (!(ptr = strchr(line, ' ')))
+	len -= 3;
+	if (!(ptr = memchr(line, ' ', len)))
 		goto out_err;
 	len = ptr - line;
 
@@ -311,8 +314,11 @@
 	memcpy(pkt->ref, line, len);
 	pkt->ref[len] = '\0';
 
+	if (len < 1)
+		goto out_err;
 	line = ptr + 1;
-	if (!(ptr = strchr(line, '\n')))
+	len -= 1;
+	if (!(ptr = memchr(line, '\n', len)))
 		goto out_err;
 	len = ptr - line;
 
```
