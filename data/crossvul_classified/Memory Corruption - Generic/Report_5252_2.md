# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5252_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5252_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 67-108 of the vulnerable file.

	/* Session key */
	sessionkey = htons(sessionkey);
	memcpy(data + (mt_direction_fromserver ? 16 : 14), &sessionkey, sizeof(sessionkey));

	/* Client type: Mac Telnet */
	memcpy(data + (mt_direction_fromserver ? 14 : 16), &mt_mactelnet_clienttype, sizeof(mt_mactelnet_clienttype));

	/* Received/sent data counter */
	counter = htonl(counter);
	memcpy(data + 18, &counter, sizeof(counter));

	/* 22 bytes header */
	packet->size = 22;
	return 22;
}

int add_control_packet(struct mt_packet *packet, enum mt_cptype cptype, void *cpdata, unsigned short data_len) {
	unsigned char *data = packet->data + packet->size;
	unsigned int act_size = data_len + (cptype == MT_CPTYPE_PLAINDATA ? 0 : MT_CPHEADER_LEN);

	/* Something is really wrong. Packets should never become over 1500 bytes */
	if (packet->size + act_size > MT_PACKET_LEN) {
		fprintf(stderr, _("add_control_packet: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
		return -1;
		//exit(1);
	}

	/* PLAINDATA isn't really a controlpacket, but we handle it here, since
	   parseControlPacket also parses raw data as PLAINDATA */
	if (cptype == MT_CPTYPE_PLAINDATA) {
		memcpy(data, cpdata, data_len);
		packet->size += data_len;
		return data_len;
	}

	/* Control Packet Magic id */
	memcpy(data, mt_mactelnet_cpmagic, sizeof(mt_mactelnet_cpmagic));

	/* Control packet type */
	data[4] = cptype;

	/* Data length */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,8 +84,9 @@
 	unsigned char *data = packet->data + packet->size;
 	unsigned int act_size = data_len + (cptype == MT_CPTYPE_PLAINDATA ? 0 : MT_CPHEADER_LEN);
 
-	/* Something is really wrong. Packets should never become over 1500 bytes */
-	if (packet->size + act_size > MT_PACKET_LEN) {
+	/* Something is really wrong. Packets should never become over 1500 bytes,
+       perform an Integer-Overflow safe check */
+	if (act_size > MT_PACKET_LEN - packet->size) {
 		fprintf(stderr, _("add_control_packet: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
 		return -1;
 		//exit(1);
@@ -149,7 +150,8 @@
 }
 
 int add_packetdata(struct mt_packet *packet, unsigned char *data, unsigned short length) {
-	if (packet->size + length > MT_PACKET_LEN) {
+	/* Integer-Overflow safe check */
+	if (length > MT_PACKET_LEN - packet->size) {
 		fprintf(stderr, _("add_control_packet: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
 		return -1;
 	}
@@ -272,7 +274,7 @@
 	unsigned short len = data_len;
 
 	/* Something is really wrong. Packets should never become over 1500 bytes */
-	if (packet->size + 4 + data_len > MT_PACKET_LEN) {
+	if (data_len > MT_PACKET_LEN - 4 - packet->size) {
 		fprintf(stderr, _("mndp_add_attribute: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
 		return -1;
 	}
```
