# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 5364_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5364_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 492-532 of the vulnerable file.

	  jpc_getuint32(in, &siz->xoff) ||
	  jpc_getuint32(in, &siz->yoff) ||
	  jpc_getuint32(in, &siz->tilewidth) ||
	  jpc_getuint32(in, &siz->tileheight) ||
	  jpc_getuint32(in, &siz->tilexoff) ||
	  jpc_getuint32(in, &siz->tileyoff) ||
	  jpc_getuint16(in, &siz->numcomps)) {
		return -1;
	}
	if (!siz->width || !siz->height || !siz->tilewidth ||
	  !siz->tileheight || !siz->numcomps) {
		return -1;
	}
	if (!(siz->comps = jas_alloc2(siz->numcomps, sizeof(jpc_sizcomp_t)))) {
		return -1;
	}
	for (i = 0; i < siz->numcomps; ++i) {
		if (jpc_getuint8(in, &tmp) ||
		  jpc_getuint8(in, &siz->comps[i].hsamp) ||
		  jpc_getuint8(in, &siz->comps[i].vsamp)) {
			jas_free(siz->comps);
			return -1;
		}
		siz->comps[i].sgnd = (tmp >> 7) & 1;
		siz->comps[i].prec = (tmp & 0x7f) + 1;
	}
	if (jas_stream_eof(in)) {
		jas_free(siz->comps);
		return -1;
	}
	return 0;
}

static int jpc_siz_putparms(jpc_ms_t *ms, jpc_cstate_t *cstate, jas_stream_t *out)
{
	jpc_siz_t *siz = &ms->parms.siz;
	unsigned int i;

	/* Eliminate compiler warning about unused variables. */
	cstate = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -512,6 +512,16 @@
 			jas_free(siz->comps);
 			return -1;
 		}
+		if (siz->comps[i].hsamp == 0 || siz->comps[i].hsamp > 255) {
+			jas_eprintf("invalid XRsiz value %d\n", siz->comps[i].hsamp);
+			jas_free(siz->comps);
+			return -1;
+		}
+		if (siz->comps[i].vsamp == 0 || siz->comps[i].vsamp > 255) {
+			jas_eprintf("invalid YRsiz value %d\n", siz->comps[i].vsamp);
+			jas_free(siz->comps);
+			return -1;
+		}
 		siz->comps[i].sgnd = (tmp >> 7) & 1;
 		siz->comps[i].prec = (tmp & 0x7f) + 1;
 	}
```
