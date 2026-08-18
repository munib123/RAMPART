# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3974_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3974_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 93-133 of the vulnerable file.


/* ************************************************************************ */

static u_int16_t concat_hash_string(struct ndpi_packet_struct *packet,
				   char *buf, u_int8_t client_hash) {
  u_int16_t offset = 22, buf_out_len = 0;
  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
    goto invalid_payload;
  u_int32_t len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4;

  /* -1 for ';' */
  if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
    goto invalid_payload;

  /* ssh.kex_algorithms [C/S] */
  strncpy(buf, (const char *)&packet->payload[offset], buf_out_len = len);
  buf[buf_out_len++] = ';';
  offset += len;

  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4 + len;

  /* ssh.encryption_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);

  if(client_hash) {
    offset += 4;

    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
      goto invalid_payload;

    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
    buf_out_len += len;
    buf[buf_out_len++] = ';';
    offset += len;
  } else
    offset += 4 + len;

  /* ssh.encryption_algorithms_server_to_client [S] */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,10 +110,14 @@
   buf[buf_out_len++] = ';';
   offset += len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.server_host_key_algorithms [None] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
   offset += 4 + len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.encryption_algorithms_client_to_server [C] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
@@ -130,6 +134,8 @@
   } else
     offset += 4 + len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.encryption_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
@@ -146,6 +152,8 @@
   } else
     offset += 4 + len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.mac_algorithms_client_to_server [C] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
@@ -162,6 +170,8 @@
   } else
     offset += 4 + len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.mac_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
@@ -195,6 +205,8 @@
   } else
     offset += 4 + len;
 
+  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
+    goto invalid_payload;
   /* ssh.compression_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
```
