# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5113_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5113_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 246-286 of the vulnerable file.

 *
 * XXX list extra formats here!
6843828.0: trust(o) len=98:00121ebbd132->00600868d659/0800
              192.168.1.1 -> 192.168.1.10/6
              vhl=45, tos=00, id=37739, frag=0000, ttl=64 tlen=84
              tcp:ports 2222->2333, seq=3452113890, ack=1540618280, flag=5018/ACK
              00 60 08 68 d6 59 00 12 1e bb d1 32 08 00 45 00     .`.h.Y.....2..E.
              00 54 93 6b 00 00 40 06 63 dd c0 a8 01 01 c0 a8     .T.k..@.c.......
              01 0a 08 ae 09 1d cd c3 13 e2 5b d3 f8 28 50 18     ..........[..(P.
              1f d4 79 21 00 00 e7 76 89 64 16 e2 19 0a 80 09     ..y!...v.d......
              31 e7 04 28 04 58 f3 d9 b1 9f 3d 65 1a db d8 61     1..(.X....=e...a
              2c 21 b6 d3 20 60 0c 8c 35 98 88 cf 20 91 0e a9     ,!...`..5.......
              1d 0b                                               ..


 */
static gboolean
parse_netscreen_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer* buf,
    char *line, int *err, gchar **err_info)
{
	int		sec;
	int		dsec;
	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
	char		direction[2];
	guint		pkt_len;
	char		cap_src[13];
	char		cap_dst[13];
	guint8		*pd;
	gchar		*p;
	int		n, i = 0;
	guint		offset = 0;
	gchar		dststr[13];

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.-](%1[io]) len=%9u:%12s->%12s/",
		   &sec, &dsec, cap_int, direction, &pkt_len, cap_src, cap_dst) < 5) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("netscreen: Can't parse packet-header");
		return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -263,27 +263,32 @@
 parse_netscreen_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer* buf,
     char *line, int *err, gchar **err_info)
 {
+	int		pkt_len;
 	int		sec;
 	int		dsec;
 	char		cap_int[NETSCREEN_MAX_INT_NAME_LENGTH];
 	char		direction[2];
-	guint		pkt_len;
 	char		cap_src[13];
 	char		cap_dst[13];
 	guint8		*pd;
 	gchar		*p;
 	int		n, i = 0;
-	guint		offset = 0;
+	int		offset = 0;
 	gchar		dststr[13];
 
 	phdr->rec_type = REC_TYPE_PACKET;
 	phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
 
-	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.-](%1[io]) len=%9u:%12s->%12s/",
+	if (sscanf(line, "%9d.%9d: %15[a-z0-9/:.-](%1[io]) len=%9d:%12s->%12s/",
 		   &sec, &dsec, cap_int, direction, &pkt_len, cap_src, cap_dst) < 5) {
 		*err = WTAP_ERR_BAD_FILE;
 		*err_info = g_strdup("netscreen: Can't parse packet-header");
 		return -1;
+	}
+	if (pkt_len < 0) {
+		*err = WTAP_ERR_BAD_FILE;
+		*err_info = g_strdup("netscreen: packet header has a negative packet length");
+		return FALSE;
 	}
 	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
 		/*
```
