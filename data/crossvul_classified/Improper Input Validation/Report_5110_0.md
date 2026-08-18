# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5110_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5110_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 80-124 of the vulnerable file.

0050 : 3924 5A04 5A49 4E47 036F 7267 0000 0200 9$Z.ZING.org....
0060 : 0100 016F 5B00 0D03 4841 4E03 5449 5703 ...o[...HAN.TIW.
0070 : 4E45 5400 C02E 0002 0001 0001 6F5B 0006 NET.........o[..
0080 : 034E 5331 C02E C02E 0002 0001 0001 6F5B .NS1..........o[
0090 : 001C 0854 414C 4945 5349 4E0D 434F 4E46 ...TALIESIN.CONF
00A0 : 4142 554C 4154 494F 4E03 434F 4D00 C042 ABULATION.COM..B
00B0 : 0001 0001 0001 51EC 0004 CE39 2406 C05B ......Q....9$..[
00C0 : 0001 0001 0001 6F5B 0004 CE39 245A C06D ......o[...9$Z.m
00D0 : 0001 0001 0001 4521 0004 187C 1F01      ......E!...|..

 */

/* Magic text to check for toshiba-ness of file */
static const char toshiba_hdr_magic[]  =
{ 'T', ' ', 'O', ' ', 'S', ' ', 'H', ' ', 'I', ' ', 'B', ' ', 'A' };
#define TOSHIBA_HDR_MAGIC_SIZE  (sizeof toshiba_hdr_magic  / sizeof toshiba_hdr_magic[0])

/* Magic text for start of packet */
static const char toshiba_rec_magic[]  = { '[', 'N', 'o', '.' };
#define TOSHIBA_REC_MAGIC_SIZE  (sizeof toshiba_rec_magic  / sizeof toshiba_rec_magic[0])

/*
 * XXX - is this the biggest packet we can get?
 */
#define TOSHIBA_MAX_PACKET_LEN	16384

static gboolean toshiba_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean toshiba_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static gboolean parse_single_hex_dump_line(char* rec, guint8 *buf,
	guint byte_offset);
static gboolean parse_toshiba_packet(FILE_T fh, struct wtap_pkthdr *phdr,
	Buffer *buf, int *err, gchar **err_info);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error
   and "*err_info" to null or an additional error string. */
static gint64 toshiba_seek_next_packet(wtap *wth, int *err, gchar **err_info)
{
	int byte;
	guint level = 0;
	gint64 cur_off;

	while ((byte = file_getc(wth->fh)) != EOF) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,11 +98,6 @@
 static const char toshiba_rec_magic[]  = { '[', 'N', 'o', '.' };
 #define TOSHIBA_REC_MAGIC_SIZE  (sizeof toshiba_rec_magic  / sizeof toshiba_rec_magic[0])
 
-/*
- * XXX - is this the biggest packet we can get?
- */
-#define TOSHIBA_MAX_PACKET_LEN	16384
-
 static gboolean toshiba_read(wtap *wth, int *err, gchar **err_info,
 	gint64 *data_offset);
 static gboolean toshiba_seek_read(wtap *wth, gint64 seek_off,
@@ -253,7 +248,8 @@
 	union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
 	char	line[TOSHIBA_LINE_LENGTH];
 	int	num_items_scanned;
-	int	pkt_len, pktnum, hr, min, sec, csec;
+	guint	pkt_len;
+	int	pktnum, hr, min, sec, csec;
 	char	channel[10], direction[10];
 	int	i, hex_lines;
 	guint8	*pd;
@@ -305,10 +301,20 @@
 
 	} while (strcmp(line, "OFFSET 0001-0203") != 0);
 
-	num_items_scanned = sscanf(line+64, "LEN=%9d", &pkt_len);
+	num_items_scanned = sscanf(line+64, "LEN=%9u", &pkt_len);
 	if (num_items_scanned != 1) {
 		*err = WTAP_ERR_BAD_FILE;
 		*err_info = g_strdup("toshiba: OFFSET line doesn't have valid LEN item");
+		return FALSE;
+	}
+	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
+		/*
+		 * Probably a corrupt capture file; don't blow up trying
+		 * to allocate space for an immensely-large packet.
+		 */
+		*err = WTAP_ERR_BAD_FILE;
+		*err_info = g_strdup_printf("toshiba: File has %u-byte packet, bigger than maximum of %u",
+		    pkt_len, WTAP_MAX_PACKET_SIZE);
 		return FALSE;
 	}
 
@@ -341,7 +347,7 @@
 	}
 
 	/* Make sure we have enough room for the packet */
-	ws_buffer_assure_space(buf, TOSHIBA_MAX_PACKET_LEN);
+	ws_buffer_assure_space(buf, pkt_len);
 	pd = ws_buffer_start_ptr(buf);
 
 	/* Calculate the number of hex dump lines, each
```
