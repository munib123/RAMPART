# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4217_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4217_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 179-219 of the vulnerable file.

    buffer[i] = tolower(buffer[i]);
}

/* **************************************** */

/*
  Return code
  -1: error (buffer too short)
   0: OK but buffer is not human readeable (so something went wrong)
   1: OK
 */
static int extractRDNSequence(struct ndpi_packet_struct *packet,
			      u_int offset, char *buffer, u_int buffer_len,
			      char *rdnSeqBuf, u_int *rdnSeqBuf_offset,
			      u_int rdnSeqBuf_len,
			      const char *label) {
  u_int8_t str_len = packet->payload[offset+4], is_printable = 1;
  char *str;
  u_int len, j;

  // packet is truncated... further inspection is not needed
  if((offset+4+str_len) >= packet->payload_packet_len)
    return(-1);

  str = (char*)&packet->payload[offset+5];

  len = (u_int)ndpi_min(str_len, buffer_len-1);
  strncpy(buffer, str, len);
  buffer[len] = '\0';

  // check string is printable
  for(j = 0; j < len; j++) {
    if(!ndpi_isprint(buffer[j])) {
      is_printable = 0;
      break;
    }
  }

  if(is_printable) {
    int rc = snprintf(&rdnSeqBuf[*rdnSeqBuf_offset],
		      rdnSeqBuf_len-(*rdnSeqBuf_offset),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,6 +196,14 @@
   char *str;
   u_int len, j;
 
+  if (*rdnSeqBuf_offset >= rdnSeqBuf_len) {
+#ifdef DEBUG_TLS
+    printf("[TLS] %s() [buffer capacity reached][%u]\n",
+           __FUNCTION__, rdnSeqBuf_len);
+#endif
+    return -1;
+  }
+
   // packet is truncated... further inspection is not needed
   if((offset+4+str_len) >= packet->payload_packet_len)
     return(-1);
@@ -235,7 +243,7 @@
 				       u_int16_t p_offset, u_int16_t certificate_len) {
   struct ndpi_packet_struct *packet = &flow->packet;
   u_int num_found = 0, i;
-  char buffer[64] = { '\0' }, rdnSeqBuf[1024] = { '\0' };
+  char buffer[64] = { '\0' }, rdnSeqBuf[2048] = { '\0' };
   u_int rdn_len = 0;
 
 #ifdef DEBUG_TLS
```
