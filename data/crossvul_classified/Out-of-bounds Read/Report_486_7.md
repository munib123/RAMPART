# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_7
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_7`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1242-1282 of the vulnerable file.

	}
	else
	{
		logger(Graphics, Warning,
		       "process_brushcache(), incompatible brush, width height %d %d", width,
		       height);
	}
}

/* Process a secondary order */
static void
process_secondary_order(STREAM s)
{
	/* The length isn't calculated correctly by the server.
	 * For very compact orders the length becomes negative
	 * so a signed integer must be used. */
	uint16 length;
	uint16 flags;
	uint8 type;
	uint8 *next_order;

	in_uint16_le(s, length);
	in_uint16_le(s, flags);	/* used by bmpcache2 */
	in_uint8(s, type);

	next_order = s->p + (sint16) length + 7;

	switch (type)
	{
		case RDP_ORDER_RAW_BMPCACHE:
			process_raw_bmpcache(s);
			break;

		case RDP_ORDER_COLCACHE:
			process_colcache(s);
			break;

		case RDP_ORDER_BMPCACHE:
			process_bmpcache(s);
			break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1259,10 +1259,16 @@
 	uint16 flags;
 	uint8 type;
 	uint8 *next_order;
+	struct stream packet = *s;
 
 	in_uint16_le(s, length);
 	in_uint16_le(s, flags);	/* used by bmpcache2 */
 	in_uint8(s, type);
+
+	if (!s_check_rem(s, length + 7))
+	{
+		rdp_protocol_error("process_secondary_order(), next order pointer would overrun stream", &packet);
+	}
 
 	next_order = s->p + (sint16) length + 7;
 
```
