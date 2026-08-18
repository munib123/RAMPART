# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1660_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1660_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 553-593 of the vulnerable file.

			break;
		case MIF_HSAMP:
			cmpt->sampperx = atoi(jas_tvparser_getval(tvp));
			break;
		case MIF_VSAMP:
			cmpt->samppery = atoi(jas_tvparser_getval(tvp));
			break;
		case MIF_PREC:
			cmpt->prec = atoi(jas_tvparser_getval(tvp));
			break;
		case MIF_SGND:
			cmpt->sgnd = atoi(jas_tvparser_getval(tvp));
			break;
		case MIF_DATA:
			if (!(cmpt->data = jas_strdup(jas_tvparser_getval(tvp)))) {
				return -1;
			}
			break;
		}
	}
	jas_tvparser_destroy(tvp);
	if (!cmpt->sampperx || !cmpt->samppery) {
		goto error;
	}
	if (mif_hdr_addcmpt(hdr, hdr->numcmpts, cmpt)) {
		goto error;
	}
	return 0;

error:
	if (cmpt) {
		mif_cmpt_destroy(cmpt);
	}
	if (tvp) {
		jas_tvparser_destroy(tvp);
	}
	return -1;
}

static int mif_hdr_put(mif_hdr_t *hdr, jas_stream_t *out)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -570,13 +570,13 @@
 			break;
 		}
 	}
+	if (!cmpt->sampperx || !cmpt->samppery) {
+		goto error;
+	}
+	if (mif_hdr_addcmpt(hdr, hdr->numcmpts, cmpt)) {
+		goto error;
+	}
 	jas_tvparser_destroy(tvp);
-	if (!cmpt->sampperx || !cmpt->samppery) {
-		goto error;
-	}
-	if (mif_hdr_addcmpt(hdr, hdr->numcmpts, cmpt)) {
-		goto error;
-	}
 	return 0;
 
 error:
```
