# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 3854_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3854_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 783-823 of the vulnerable file.

		break;
	}
	if ((unsigned int)curanswer == header.ancount)
		return std::make_pair((unsigned char*)NULL,"No A, AAAA or PTR type answers (" + ConvToStr(header.ancount) + " answers)");

	if (i + rr.rdlength > (unsigned int)length)
		return std::make_pair((unsigned char*)NULL,"Resource record larger than stated");

	if (rr.rdlength > 1023)
		return std::make_pair((unsigned char*)NULL,"Resource record too large");

	this->ttl = rr.ttl;

	switch (rr.type)
	{
		/*
		 * CNAME and PTR are compressed.  We need to decompress them.
		 */
		case DNS_QUERY_CNAME:
		case DNS_QUERY_PTR:
			o = 0;
			q = 0;
			while (q == 0 && i < length && o + 256 < 1023)
			{
				/* DN label found (byte over 63) */
				if (header.payload[i] > 63)
				{
					memcpy(&ptr,&header.payload[i],2);

					i = ntohs(ptr);

					/* check that highest two bits are set. if not, we've been had */
					if (!(i & DN_COMP_BITMASK))
						return std::make_pair((unsigned char *) NULL, "DN label decompression header is bogus");

					/* mask away the two highest bits. */
					i &= ~DN_COMP_BITMASK;

					/* and decrease length by 12 bytes. */
					i =- 12;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -800,6 +800,8 @@
 		 */
 		case DNS_QUERY_CNAME:
 		case DNS_QUERY_PTR:
+		{
+			unsigned short lowest_pos = length;
 			o = 0;
 			q = 0;
 			while (q == 0 && i < length && o + 256 < 1023)
@@ -812,14 +814,18 @@
 					i = ntohs(ptr);
 
 					/* check that highest two bits are set. if not, we've been had */
-					if (!(i & DN_COMP_BITMASK))
+					if ((i & DN_COMP_BITMASK) != DN_COMP_BITMASK)
 						return std::make_pair((unsigned char *) NULL, "DN label decompression header is bogus");
 
 					/* mask away the two highest bits. */
 					i &= ~DN_COMP_BITMASK;
 
 					/* and decrease length by 12 bytes. */
-					i =- 12;
+					i -= 12;
+
+					if (i >= lowest_pos)
+						return std::make_pair((unsigned char *) NULL, "Invalid decompression pointer");
+					lowest_pos = i;
 				}
 				else
 				{
@@ -843,6 +849,7 @@
 				}
 			}
 			res[o] = 0;
+		}
 		break;
 		case DNS_QUERY_AAAA:
 			if (rr.rdlength != sizeof(struct in6_addr))
```
