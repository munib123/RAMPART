# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3547_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3547_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.

	}

	if ((skb = alloc_skb(len, GFP_ATOMIC)) == NULL)
		return;

	/*
	 *	Space for AX.25 header and PID.
	 */
	skb_reserve(skb, AX25_BPQ_HEADER_LEN + AX25_MAX_HEADER_LEN + 1);

	dptr = skb_put(skb, skb_tailroom(skb));

	lci1 = (rose->lci >> 8) & 0x0F;
	lci2 = (rose->lci >> 0) & 0xFF;

	switch (frametype) {
	case ROSE_CALL_REQUEST:
		*dptr++ = ROSE_GFI | lci1;
		*dptr++ = lci2;
		*dptr++ = frametype;
		*dptr++ = 0xAA;
		memcpy(dptr, &rose->dest_addr,  ROSE_ADDR_LEN);
		dptr   += ROSE_ADDR_LEN;
		memcpy(dptr, &rose->source_addr, ROSE_ADDR_LEN);
		dptr   += ROSE_ADDR_LEN;
		memcpy(dptr, buffer, faclen);
		dptr   += faclen;
		break;

	case ROSE_CALL_ACCEPTED:
		*dptr++ = ROSE_GFI | lci1;
		*dptr++ = lci2;
		*dptr++ = frametype;
		*dptr++ = 0x00;		/* Address length */
		*dptr++ = 0;		/* Facilities length */
		break;

	case ROSE_CLEAR_REQUEST:
		*dptr++ = ROSE_GFI | lci1;
		*dptr++ = lci2;
		*dptr++ = frametype;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,7 +142,7 @@
 		*dptr++ = ROSE_GFI | lci1;
 		*dptr++ = lci2;
 		*dptr++ = frametype;
-		*dptr++ = 0xAA;
+		*dptr++ = ROSE_CALL_REQ_ADDR_LEN_VAL;
 		memcpy(dptr, &rose->dest_addr,  ROSE_ADDR_LEN);
 		dptr   += ROSE_ADDR_LEN;
 		memcpy(dptr, &rose->source_addr, ROSE_ADDR_LEN);
@@ -246,12 +246,16 @@
 	do {
 		switch (*p & 0xC0) {
 		case 0x00:
+			if (len < 2)
+				return -1;
 			p   += 2;
 			n   += 2;
 			len -= 2;
 			break;
 
 		case 0x40:
+			if (len < 3)
+				return -1;
 			if (*p == FAC_NATIONAL_RAND)
 				facilities->rand = ((p[1] << 8) & 0xFF00) + ((p[2] << 0) & 0x00FF);
 			p   += 3;
@@ -260,32 +264,48 @@
 			break;
 
 		case 0x80:
+			if (len < 4)
+				return -1;
 			p   += 4;
 			n   += 4;
 			len -= 4;
 			break;
 
 		case 0xC0:
+			if (len < 2)
+				return -1;
 			l = p[1];
+			if (len < 2 + l)
+				return -1;
 			if (*p == FAC_NATIONAL_DEST_DIGI) {
 				if (!fac_national_digis_received) {
+					if (l < AX25_ADDR_LEN)
+						return -1;
 					memcpy(&facilities->source_digis[0], p + 2, AX25_ADDR_LEN);
 					facilities->source_ndigis = 1;
 				}
 			}
 			else if (*p == FAC_NATIONAL_SRC_DIGI) {
 				if (!fac_national_digis_received) {
+					if (l < AX25_ADDR_LEN)
+						return -1;
 					memcpy(&facilities->dest_digis[0], p + 2, AX25_ADDR_LEN);
 					facilities->dest_ndigis = 1;
 				}
 			}
 			else if (*p == FAC_NATIONAL_FAIL_CALL) {
+				if (l < AX25_ADDR_LEN)
+					return -1;
 				memcpy(&facilities->fail_call, p + 2, AX25_ADDR_LEN);
 			}
 			else if (*p == FAC_NATIONAL_FAIL_ADD) {
+				if (l < 1 + ROSE_ADDR_LEN)
+					return -1;
 				memcpy(&facilities->fail_addr, p + 3, ROSE_ADDR_LEN);
 			}
 			else if (*p == FAC_NATIONAL_DIGIS) {
+				if (l % AX25_ADDR_LEN)
+					return -1;
 				fac_national_digis_received = 1;
 				facilities->source_ndigis = 0;
 				facilities->dest_ndigis   = 0;
@@ -319,24 +339,32 @@
 	do {
 		switch (*p & 0xC0) {
 		case 0x00:
+			if (len < 2)
+				return -1;
 			p   += 2;
 			n   += 2;
 			len -= 2;
 			break;
 
 		case 0x40:
+			if (len < 3)
+				return -1;
 			p   += 3;
 			n   += 3;
 			len -= 3;
 			break;
 
 		case 0x80:
+			if (len < 4)
+				return -1;
 			p   += 4;
 			n   += 4;
 			len -= 4;
 			break;
 
 		case 0xC0:
+			if (len < 2)
+				return -1;
 			l = p[1];
 
 			/* Prevent overflows*/
@@ -365,49 +393,44 @@
 	return n;
 }
 
-int rose_parse_facilities(unsigned char *p,
+int rose_parse_facilities(unsigned char *p, unsigned packet_len,
 	struct rose_facilities_struct *facilities)
 {
 	int facilities_len, len;
 
 	facilities_len = *p++;
 
-	if (facilities_len == 0)
+	if (facilities_len == 0 || (unsigned)facilities_len > packet_len)
 		return 0;
 
-	while (facilities_len > 0) {
-		if (*p == 0x00) {
-			facilities_len--;
-			p++;
-
-			switch (*p) {
-			case FAC_NATIONAL:		/* National */
-				len = rose_parse_national(p + 1, facilities, facilities_len - 1);
-				if (len < 0)
-					return 0;
-				facilities_len -= len + 1;
-				p += len + 1;
-				break;
-
-			case FAC_CCITT:		/* CCITT */
-				len = rose_parse_ccitt(p + 1, facilities, facilities_len - 1);
-				if (len < 0)
-					return 0;
-				facilities_len -= len + 1;
-				p += len + 1;
-				break;
-
-			default:
-				printk(KERN_DEBUG "ROSE: rose_parse_facilities - unknown facilities family %02X\n", *p);
-				facilities_len--;
-				p++;
-				break;
-			}
-		} else
-			break;	/* Error in facilities format */
-	}
-
-	return 1;
+	while (facilities_len >= 3 && *p == 0x00) {
+		facilities_len--;
+		p++;
+
+		switch (*p) {
+		case FAC_NATIONAL:		/* National */
+			len = rose_parse_national(p + 1, facilities, facilities_len - 1);
+			break;
+
+		case FAC_CCITT:		/* CCITT */
+			len = rose_parse_ccitt(p + 1, facilities, facilities_len - 1);
+			break;
+
+		default:
+			printk(KERN_DEBUG "ROSE: rose_parse_facilities - unknown facilities family %02X\n", *p);
+			len = 1;
+			break;
+		}
+
+		if (len < 0)
+			return 0;
+		if (WARN_ON(len >= facilities_len))
+			return 0;
+		facilities_len -= len + 1;
+		p += len + 1;
+	}
+
+	return facilities_len == 0;
 }
 
 static int rose_create_facilities(unsigned char *buffer, struct rose_sock *rose)
```
