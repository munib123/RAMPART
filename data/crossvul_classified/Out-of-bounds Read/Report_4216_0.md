# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4216_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4216_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 55-96 of the vulnerable file.

int8_t check_pkid_and_detect_hmac_size(const u_int8_t * payload) {
  // try to guess
  if(get_packet_id(payload, P_HMAC_160) == 1)
    return P_HMAC_160;
  
  if(get_packet_id(payload, P_HMAC_128) == 1)    
    return P_HMAC_128;
  
  return(-1);
}

void ndpi_search_openvpn(struct ndpi_detection_module_struct* ndpi_struct,
                         struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;
  const u_int8_t * ovpn_payload = packet->payload;
  const u_int8_t * session_remote;
  u_int8_t opcode;
  u_int8_t alen;
  int8_t hmac_size;
  int8_t failed = 0;

  if(packet->payload_packet_len >= 40) {
    // skip openvpn TCP transport packet size
    if(packet->tcp != NULL)
      ovpn_payload += 2;

    opcode = ovpn_payload[0] & P_OPCODE_MASK;

    if(packet->udp) {
#ifdef DEBUG
      printf("[packet_id: %u][opcode: %u][Packet ID: %d][%u <-> %u][len: %u]\n",
	     flow->num_processed_pkts,
	     opcode, check_pkid_and_detect_hmac_size(ovpn_payload),
	     htons(packet->udp->source), htons(packet->udp->dest), packet->payload_packet_len);	   
#endif
      
      if(
	 (flow->num_processed_pkts == 1)
	 && (
	     ((packet->payload_packet_len == 112)
	      && ((opcode == 168) || (opcode == 192))
	      )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,11 +72,12 @@
   u_int8_t alen;
   int8_t hmac_size;
   int8_t failed = 0;
-
-  if(packet->payload_packet_len >= 40) {
+  /* No u_ */int16_t ovpn_payload_len = packet->payload_packet_len;
+  
+  if(ovpn_payload_len >= 40) {
     // skip openvpn TCP transport packet size
     if(packet->tcp != NULL)
-      ovpn_payload += 2;
+      ovpn_payload += 2, ovpn_payload_len -= 2;;
 
     opcode = ovpn_payload[0] & P_OPCODE_MASK;
 
@@ -85,16 +86,16 @@
       printf("[packet_id: %u][opcode: %u][Packet ID: %d][%u <-> %u][len: %u]\n",
 	     flow->num_processed_pkts,
 	     opcode, check_pkid_and_detect_hmac_size(ovpn_payload),
-	     htons(packet->udp->source), htons(packet->udp->dest), packet->payload_packet_len);	   
+	     htons(packet->udp->source), htons(packet->udp->dest), ovpn_payload_len);	   
 #endif
       
       if(
 	 (flow->num_processed_pkts == 1)
 	 && (
-	     ((packet->payload_packet_len == 112)
+	     ((ovpn_payload_len == 112)
 	      && ((opcode == 168) || (opcode == 192))
 	      )
-	     || ((packet->payload_packet_len == 80)
+	     || ((ovpn_payload_len == 80)
 		 && ((opcode == 184) || (opcode == 88) || (opcode == 160) || (opcode == 168) || (opcode == 200)))
 	     )) {
 	NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
@@ -119,22 +120,30 @@
       hmac_size = check_pkid_and_detect_hmac_size(ovpn_payload);
 
       if(hmac_size > 0) {
-        alen = ovpn_payload[P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)];
+	u_int16_t offset = P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size);
+	  
+        alen = ovpn_payload[offset];
+	
         if (alen > 0) {
-	  session_remote = ovpn_payload + P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size) + 1 + alen * 4;
+	  offset += 1 + alen * 4;
 
-          if(memcmp(flow->ovpn_session_id, session_remote, 8) == 0) {
-	    NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
-	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
-	    return;
-	  } else {
-            NDPI_LOG_DBG2(ndpi_struct,
-		   "key mismatch: %02x%02x%02x%02x%02x%02x%02x%02x\n",
-		   session_remote[0], session_remote[1], session_remote[2], session_remote[3],
-		   session_remote[4], session_remote[5], session_remote[6], session_remote[7]);
-            failed = 1;
-          }
-        } else
+	  if((offset+8) <= ovpn_payload_len) {
+	    session_remote = &ovpn_payload[offset];
+	    
+	    if(memcmp(flow->ovpn_session_id, session_remote, 8) == 0) {
+	      NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
+	      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
+	      return;
+	    } else {
+	      NDPI_LOG_DBG2(ndpi_struct,
+			    "key mismatch: %02x%02x%02x%02x%02x%02x%02x%02x\n",
+			    session_remote[0], session_remote[1], session_remote[2], session_remote[3],
+			    session_remote[4], session_remote[5], session_remote[6], session_remote[7]);
+	      failed = 1;
+	    }
+	  } else
+	    failed = 1;
+	} else
           failed = 1;
       } else
         failed = 1;
```
