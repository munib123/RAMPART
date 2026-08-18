# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_14
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_14`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 55-95 of the vulnerable file.

		if (cla == SC_ASN1_TAG_APPLICATION) {
			switch (tag) {
				case 0x1A:
					iccsn_found = 1;
					if (iccsn && iccsn_len) {
						memcpy(iccsn, p, MIN(tag_len, *iccsn_len));
						*iccsn_len = MIN(tag_len, *iccsn_len);
					}
					break;
				case 0x1F20:
					chn_found = 1;
					if (chn && chn_len) {
						memcpy(chn, p, MIN(tag_len, *chn_len));
						*chn_len = MIN(tag_len, *chn_len);
					}
					break;
			}
		}

		p += tag_len;
		left -= (p - gdo);
	}

	if (!iccsn_found && iccsn_len)
		*iccsn_len = 0;
	if (!chn_found && chn_len)
		*chn_len = 0;

	return r;
}



int
sc_parse_ef_gdo(struct sc_card *card,
		unsigned char *iccsn, size_t *iccsn_len,
		unsigned char *chn, size_t *chn_len)
{
	struct sc_context *ctx;
	struct sc_path path;
	struct sc_file *file;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 		}
 
 		p += tag_len;
-		left -= (p - gdo);
+		left = gdo_len - (p - gdo);
 	}
 
 	if (!iccsn_found && iccsn_len)
```
