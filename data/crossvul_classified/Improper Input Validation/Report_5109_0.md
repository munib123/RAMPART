# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5109_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5109_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 231-272 of the vulnerable file.

{
	if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
		return FALSE;

	if (!parse_toshiba_packet(wth->random_fh, phdr, buf, err, err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/* Parses a packet. */
static gboolean
parse_toshiba_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	char	line[TOSHIBA_LINE_LENGTH];
	int	num_items_scanned;
	guint	pkt_len;
	int	pktnum, hr, min, sec, csec;
	char	channel[10], direction[10];
	int	i, hex_lines;
	guint8	*pd;

	/* Our file pointer should be on the line containing the
	 * summary information for a packet. Read in that line and
	 * extract the useful information
	 */
	if (file_gets(line, TOSHIBA_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh, err_info);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	/* Find text in line after "[No.". Limit the length of the
	 * two strings since we have fixed buffers for channel[] and
	 * direction[] */
	num_items_scanned = sscanf(line, "%9d] %2d:%2d:%2d.%9d %9s %9s",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,8 +248,7 @@
 	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
 	char	line[TOSHIBA_LINE_LENGTH];
 	int	num_items_scanned;
-	guint	pkt_len;
-	int	pktnum, hr, min, sec, csec;
+	int	pkt_len, pktnum, hr, min, sec, csec;
 	char	channel[10], direction[10];
 	int	i, hex_lines;
 	guint8	*pd;
@@ -301,10 +300,15 @@
 
 	} while (strcmp(line, "OFFSET 0001-0203") != 0);
 
-	num_items_scanned = sscanf(line+64, "LEN=%9u", &pkt_len);
+	num_items_scanned = sscanf(line+64, "LEN=%9d", &pkt_len);
 	if (num_items_scanned != 1) {
 		*err = WTAP_ERR_BAD_FILE;
 		*err_info = g_strdup("toshiba: OFFSET line doesn't have valid LEN item");
+		return FALSE;
+	}
+	if (pkt_len < 0) {
+		*err = WTAP_ERR_BAD_FILE;
+		*err_info = g_strdup("toshiba: packet header has a negative packet length");
 		return FALSE;
 	}
 	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
```
