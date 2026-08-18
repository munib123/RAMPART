# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5114_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5114_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 52-97 of the vulnerable file.

 *    but I don't think we fully *supported* it at that point.  Now
 *    that we do, we have the infrastructure to support this, except
 *    that we currently have no way to translate interface IDs to
 *    interface names in the "frame" dissector or to supply interface
 *    information as part of the packet metadata from Wiretap modules.
 *    That should be fixed so that we can show interface information,
 *    such as the interface name, in packet dissections from, for example,
 *    pcap-NG captures.
 */

static gboolean info_line(const gchar *line);
static gint64 netscreen_seek_next_packet(wtap *wth, int *err, gchar **err_info,
	char *hdr);
static gboolean netscreen_check_file_type(wtap *wth, int *err,
	gchar **err_info);
static gboolean netscreen_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean netscreen_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf,
	int *err, gchar **err_info);
static int parse_netscreen_rec_hdr(struct wtap_pkthdr *phdr, const char *line,
	char *cap_int, gboolean *cap_dir, char *cap_dst,
	int *err, gchar **err_info);
static gboolean parse_netscreen_hex_dump(FILE_T fh, int pkt_len,
	const char *cap_int, const char *cap_dst, struct wtap_pkthdr *phdr,
	Buffer* buf, int *err, gchar **err_info);
static int parse_single_hex_dump_line(char* rec, guint8 *buf,
	guint byte_offset);

/* Returns TRUE if the line appears to be a line with protocol info.
   Otherwise it returns FALSE. */
static gboolean info_line(const gchar *line)
{
	int i=NETSCREEN_SPACES_ON_INFO_LINE;

	while (i-- > 0) {
		if (g_ascii_isspace(*line)) {
			line++;
			continue;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,12 +69,8 @@
 static gboolean netscreen_seek_read(wtap *wth, gint64 seek_off,
 	struct wtap_pkthdr *phdr, Buffer *buf,
 	int *err, gchar **err_info);
-static int parse_netscreen_rec_hdr(struct wtap_pkthdr *phdr, const char *line,
-	char *cap_int, gboolean *cap_dir, char *cap_dst,
-	int *err, gchar **err_info);
-static gboolean parse_netscreen_hex_dump(FILE_T fh, int pkt_len,
-	const char *cap_int, const char *cap_dst, struct wtap_pkthdr *phdr,
-	Buffer* buf, int *err, gchar **err_info);
+static gboolean parse_netscreen_packet(FILE_T fh, struct wtap_pkthdr *phdr,
+	Buffer* buf, char *line, int *err, gchar **err_info);
 static int parse_single_hex_dump_line(char* rec, guint8 *buf,
 	guint byte_offset);
 
@@ -191,27 +187,16 @@
     gint64 *data_offset)
 {
 	gint64		offset;
-	int		pkt_len;
 	char		line[NETSCREEN_LINE_LENGTH];
-	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
-	gboolean	cap_dir;
-	char		cap_dst[13];
 
 	/* Find the next packet */
 	offset = netscreen_seek_next_packet(wth, err, err_info, line);
 	if (offset < 0)
 		return FALSE;
 
-	/* Parse the header */
-	pkt_len = parse_netscreen_rec_hdr(&wth->phdr, line, cap_int, &cap_dir,
-	    cap_dst, err, err_info);
-	if (pkt_len == -1)
-		return FALSE;
-
-	/* Convert the ASCII hex dump to binary data, and fill in some
-	   struct wtap_pkthdr fields */
-	if (!parse_netscreen_hex_dump(wth->fh, pkt_len, cap_int,
-	    cap_dst, &wth->phdr, wth->frame_buffer, err, err_info))
+	/* Parse the header and convert the ASCII hex dump to binary data */
+	if (!parse_netscreen_packet(wth->fh, &wth->phdr,
+	    wth->frame_buffer, line, err, err_info))
 		return FALSE;
 
 	/*
@@ -239,11 +224,7 @@
 	struct wtap_pkthdr *phdr, Buffer *buf,
 	int *err, gchar **err_info)
 {
-	int		pkt_len;
 	char		line[NETSCREEN_LINE_LENGTH];
-	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
-	gboolean	cap_dir;
-	char		cap_dst[13];
 
 	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
 		return FALSE;
@@ -257,15 +238,8 @@
 		return FALSE;
 	}
 
-	pkt_len = parse_netscreen_rec_hdr(phdr, line, cap_int, &cap_dir,
-	    cap_dst, err, err_info);
-	if (pkt_len == -1)
-		return FALSE;
-
-	if (!parse_netscreen_hex_dump(wth->random_fh, pkt_len, cap_int,
-	    cap_dst, phdr, buf, err, err_info))
-		return FALSE;
-	return TRUE;
+	return parse_netscreen_packet(wth->random_fh, phdr, buf, line,
+	    err, err_info);
 }
 
 /* Parses a packet record header. There are a few possible formats:
@@ -285,49 +259,54 @@
 
 
  */
-static int
-parse_netscreen_rec_hdr(struct wtap_pkthdr *phdr, const char *line, char *cap_int,
-    gboolean *cap_dir, char *cap_dst, int *err, gchar **err_info)
-{
-	int	sec;
-	int	dsec, pkt_len;
-	char	direction[2];
-	char	cap_src[13];
+static gboolean
+parse_netscreen_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer* buf,
+    char *line, int *err, gchar **err_info)
+{
+	int		sec;
+	int		dsec;
+	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
+	char		direction[2];
+	guint		pkt_len;
+	char		cap_src[13];
+	char		cap_dst[13];
+	guint8		*pd;
+	gchar		*p;
+	int		n, i = 0;
+	guint		offset = 0;
+	gchar		dststr[13];
 
 	phdr->rec_type = REC_TYPE_PACKET;
 	phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
 
-	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.-](%1[io]) len=%9d:%12s->%12s/",
+	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.-](%1[io]) len=%9u:%12s->%12s/",
 		   &sec, &dsec, cap_int, direction, &pkt_len, cap_src, cap_dst) < 5) {
 		*err = WTAP_ERR_BAD_FILE;
 		*err_info = g_strdup("netscreen: Can't parse packet-header");
 		return -1;
 	}
-
-	*cap_dir = (direction[0] == 'o' ? NETSCREEN_EGRESS : NETSCREEN_INGRESS);
+	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
+		/*
+		 * Probably a corrupt capture file; don't blow up trying
+		 * to allocate space for an immensely-large packet.
+		 */
+		*err = WTAP_ERR_BAD_FILE;
+		*err_info = g_strdup_printf("netscreen: File has %u-byte packet, bigger than maximum of %u",
+		    pkt_len, WTAP_MAX_PACKET_SIZE);
+		return FALSE;
+	}
+
+	/*
+	 * If direction[0] is 'o', the direction is NETSCREEN_EGRESS,
+	 * otherwise it's NETSCREEN_INGRESS.
+	 */
 
 	phdr->ts.secs  = sec;
 	phdr->ts.nsecs = dsec * 100000000;
 	phdr->len = pkt_len;
 
-	return pkt_len;
-}
-
-/* Converts ASCII hex dump to binary data, and fills in some struct
-   wtap_pkthdr fields.  Returns TRUE on success and FALSE on any error. */
-static gboolean
-parse_netscreen_hex_dump(FILE_T fh, int pkt_len, const char *cap_int,
-    const char *cap_dst, struct wtap_pkthdr *phdr, Buffer* buf,
-    int *err, gchar **err_info)
-{
-	guint8	*pd;
-	gchar	line[NETSCREEN_LINE_LENGTH];
-	gchar	*p;
-	int	n, i = 0, offset = 0;
-	gchar	dststr[13];
-
 	/* Make sure we have enough room for the packet */
-	ws_buffer_assure_space(buf, NETSCREEN_MAX_PACKET_LEN);
+	ws_buffer_assure_space(buf, pkt_len);
 	pd = ws_buffer_start_ptr(buf);
 
 	while(1) {
@@ -373,7 +352,7 @@
 		/* If there is no more data and the line was not empty,
 		 * then there must be an error in the file
 		 */
-		if(n == -1) {
+		if (n == -1) {
 			*err = WTAP_ERR_BAD_FILE;
 			*err_info = g_strdup("netscreen: cannot parse hex-data");
 			return FALSE;
@@ -385,7 +364,7 @@
 		/* If there was more hex-data than was announced in the len=x
 		 * header, then then there must be an error in the file
 		 */
-		if(offset > pkt_len) {
+		if (offset > pkt_len) {
 			*err = WTAP_ERR_BAD_FILE;
 			*err_info = g_strdup("netscreen: too much hex-data");
 			return FALSE;
```
