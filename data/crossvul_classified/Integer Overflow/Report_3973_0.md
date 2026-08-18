# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3973_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3973_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.


static void ndpi_int_ssh_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow) {
  if(flow->extra_packets_func != NULL)
    return;

  flow->guessed_host_protocol_id = flow->guessed_protocol_id = NDPI_PROTOCOL_SSH;
  
  /* This is necessary to inform the core to call this dissector again */
  flow->check_extra_packets = 1;
  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = search_ssh_again;
  
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSH, NDPI_PROTOCOL_UNKNOWN);
}

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

  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
    goto invalid_payload;
  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4 + len;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,7 +95,7 @@
 
 static u_int16_t concat_hash_string(struct ndpi_packet_struct *packet,
 				   char *buf, u_int8_t client_hash) {
-  u_int16_t offset = 22, buf_out_len = 0;
+  u_int32_t offset = 22, buf_out_len = 0;
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   u_int32_t len = ntohl(*(u_int32_t*)&packet->payload[offset]);
@@ -114,6 +114,8 @@
     goto invalid_payload;
   /* ssh.server_host_key_algorithms [None] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
+  if (len > UINT32_MAX - 4 - offset)
+    goto invalid_payload;
   offset += 4 + len;
 
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
@@ -121,106 +123,106 @@
   /* ssh.encryption_algorithms_client_to_server [C] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(client_hash) {
-    offset += 4;
-
     if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
       goto invalid_payload;
 
     strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
     buf_out_len += len;
     buf[buf_out_len++] = ';';
-    offset += len;
-  } else
-    offset += 4 + len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   /* ssh.encryption_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(!client_hash) {
-    offset += 4;
-
     if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
       goto invalid_payload;
 
     strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
     buf_out_len += len;
     buf[buf_out_len++] = ';';
-    offset += len;
-  } else
-    offset += 4 + len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   /* ssh.mac_algorithms_client_to_server [C] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(client_hash) {
-    offset += 4;
-
     if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
       goto invalid_payload;
 
     strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
     buf_out_len += len;
     buf[buf_out_len++] = ';';
-    offset += len;
-  } else
-    offset += 4 + len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   /* ssh.mac_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(!client_hash) {
-    offset += 4;
-
     if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
       goto invalid_payload;
 
     strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
     buf_out_len += len;
     buf[buf_out_len++] = ';';
-    offset += len;
-  } else
-    offset += 4 + len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   /* ssh.compression_algorithms_client_to_server [C] */
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(client_hash) {
-    offset += 4;
-
-    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
-      goto invalid_payload;
-
-    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
-    buf_out_len += len;
-    offset += len;
-  } else
-    offset += 4 + len;
+    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
+      goto invalid_payload;
+
+    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
+    buf_out_len += len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
     goto invalid_payload;
   /* ssh.compression_algorithms_server_to_client [S] */
   len = ntohl(*(u_int32_t*)&packet->payload[offset]);
 
+  offset += 4;
   if(!client_hash) {
-    offset += 4;
-
-    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
-      goto invalid_payload;
-
-    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
-    buf_out_len += len;
-    offset += len;
-  } else
-    offset += 4 + len;
+    if((offset >= packet->payload_packet_len) || (len >= packet->payload_packet_len-offset-1))
+      goto invalid_payload;
+
+    strncpy(&buf[buf_out_len], (const char *)&packet->payload[offset], len);
+    buf_out_len += len;
+  }
+  if (len > UINT32_MAX - offset)
+    goto invalid_payload;
+  offset += len;
 
   /* ssh.languages_client_to_server [None] */
 
```
