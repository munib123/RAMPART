# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5111_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5111_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 313-354 of the vulnerable file.

		}
		return FALSE;
	}

	/* Parse the header and convert the ASCII hex dump to binary data */
	return parse_cosine_packet(wth->random_fh, phdr, buf, line, err,
	    err_info);
}

/* Parses a packet record header. There are two possible formats:
    1) output to a control blade with date and time
        2002-5-10,20:1:31.4:  l2-tx (FR:3/7/1:1), Length:18, Pro:0, Off:0, Pri:0, RM:0, Err:0 [0x4000, 0x0]
    2) output to PE without date and time
        l2-tx (FR:3/7/1:1), Length:18, Pro:0, Off:0, Pri:0, RM:0, Err:0 [0x4000, 0x0] */
static gboolean
parse_cosine_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
    char *line, int *err, gchar **err_info)
{
	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	int	num_items_scanned;
	int	yy, mm, dd, hr, min, sec, csec;
	guint	pkt_len;
	int	pro, off, pri, rm, error;
	guint	code1, code2;
	char	if_name[COSINE_MAX_IF_NAME_LEN] = "", direction[6] = "";
	struct	tm tm;
	guint8 *pd;
	int	i, hex_lines, n, caplen = 0;

	if (sscanf(line, "%4d-%2d-%2d,%2d:%2d:%2d.%9d:",
		   &yy, &mm, &dd, &hr, &min, &sec, &csec) == 7) {
		/* appears to be output to a control blade */
		num_items_scanned = sscanf(line,
		   "%4d-%2d-%2d,%2d:%2d:%2d.%9d: %5s (%127[A-Za-z0-9/:]), Length:%9u, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
			&yy, &mm, &dd, &hr, &min, &sec, &csec,
				   direction, if_name, &pkt_len,
				   &pro, &off, &pri, &rm, &error,
				   &code1, &code2);

		if (num_items_scanned != 17) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("cosine: purported control blade line doesn't have code values");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,8 +330,7 @@
 {
 	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
 	int	num_items_scanned;
-	int	yy, mm, dd, hr, min, sec, csec;
-	guint	pkt_len;
+	int	yy, mm, dd, hr, min, sec, csec, pkt_len;
 	int	pro, off, pri, rm, error;
 	guint	code1, code2;
 	char	if_name[COSINE_MAX_IF_NAME_LEN] = "", direction[6] = "";
@@ -343,7 +342,7 @@
 		   &yy, &mm, &dd, &hr, &min, &sec, &csec) == 7) {
 		/* appears to be output to a control blade */
 		num_items_scanned = sscanf(line,
-		   "%4d-%2d-%2d,%2d:%2d:%2d.%9d: %5s (%127[A-Za-z0-9/:]), Length:%9u, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
+		   "%4d-%2d-%2d,%2d:%2d:%2d.%9d: %5s (%127[A-Za-z0-9/:]), Length:%9d, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
 			&yy, &mm, &dd, &hr, &min, &sec, &csec,
 				   direction, if_name, &pkt_len,
 				   &pro, &off, &pri, &rm, &error,
@@ -357,7 +356,7 @@
 	} else {
 		/* appears to be output to PE */
 		num_items_scanned = sscanf(line,
-		   "%5s (%127[A-Za-z0-9/:]), Length:%9u, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
+		   "%5s (%127[A-Za-z0-9/:]), Length:%9d, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
 				   direction, if_name, &pkt_len,
 				   &pro, &off, &pri, &rm, &error,
 				   &code1, &code2);
@@ -368,6 +367,11 @@
 			return FALSE;
 		}
 		yy = mm = dd = hr = min = sec = csec = 0;
+	}
+	if (pkt_len < 0) {
+		*err = WTAP_ERR_BAD_FILE;
+		*err_info = g_strdup("cosine: packet header has a negative packet length");
+		return FALSE;
 	}
 	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
 		/*
```
