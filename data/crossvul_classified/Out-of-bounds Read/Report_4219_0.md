# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4219_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4219_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.



static void ndpi_int_oracle_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ORACLE, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_oracle(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search ORACLE\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculating ORACLE over tcp\n");
    /* Oracle Database 9g,10g,11g */
    if ((dport == 1521 || sport == 1521)
	&&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
	     || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01)) 
	     && (packet->payload[1] != 0x00)
	     && (packet->payload[2] == 0x00)
		 && (packet->payload[3] == 0x00)))) {
      NDPI_LOG_INFO(ndpi_struct, "found oracle\n");
      ndpi_int_oracle_add_connection(ndpi_struct, flow);
    } else if (packet->payload_packet_len == 213 && packet->payload[0] == 0x00 &&
               packet->payload[1] == 0xd5 && packet->payload[2] == 0x00 &&
               packet->payload[3] == 0x00 ) {
      NDPI_LOG_INFO(ndpi_struct, "found oracle\n");
      ndpi_int_oracle_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_oracle_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
     NDPI_LOG_DBG2(ndpi_struct, "calculating ORACLE over tcp\n");
     /* Oracle Database 9g,10g,11g */
     if ((dport == 1521 || sport == 1521)
-	&&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
+	&&  (((packet->payload_packet_len >= 3 && packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
 	     || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01)) 
 	     && (packet->payload[1] != 0x00)
 	     && (packet->payload[2] == 0x00)
```
