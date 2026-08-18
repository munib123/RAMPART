# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4522_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4522_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 646-686 of the vulnerable file.


	return doffset >= finish;
}

/* read_fru_area  -  fill in frubuf[offset:length] from the FRU[offset:length]
*
* @intf:   ipmi interface
* @fru: fru info
* @id:     fru id
* @offset: offset into buffer
* @length: how much to read
* @frubuf: buffer read into
*
* returns -1 on error
* returns 0 if successful
*/
int
read_fru_area(struct ipmi_intf * intf, struct fru_info *fru, uint8_t id,
			uint32_t offset, uint32_t length, uint8_t *frubuf)
{
	uint32_t off = offset, tmp, finish;
	struct ipmi_rs * rsp;
	struct ipmi_rq req;
	uint8_t msg_data[4];

	if (offset > fru->size) {
		lprintf(LOG_ERR, "Read FRU Area offset incorrect: %d > %d",
			offset, fru->size);
		return -1;
	}

	finish = offset + length;
	if (finish > fru->size) {
		finish = fru->size;
		lprintf(LOG_NOTICE, "Read FRU Area length %d too large, "
			"Adjusting to %d",
			offset + length, finish - offset);
	}

	memset(&req, 0, sizeof(req));
	req.msg.netfn = IPMI_NETFN_STORAGE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -663,7 +663,10 @@
 read_fru_area(struct ipmi_intf * intf, struct fru_info *fru, uint8_t id,
 			uint32_t offset, uint32_t length, uint8_t *frubuf)
 {
-	uint32_t off = offset, tmp, finish;
+	uint32_t off = offset;
+	uint32_t tmp;
+	uint32_t finish;
+	uint32_t size_left_in_buffer;
 	struct ipmi_rs * rsp;
 	struct ipmi_rq req;
 	uint8_t msg_data[4];
@@ -676,10 +679,12 @@
 
 	finish = offset + length;
 	if (finish > fru->size) {
+		memset(frubuf + fru->size, 0, length - fru->size);
 		finish = fru->size;
 		lprintf(LOG_NOTICE, "Read FRU Area length %d too large, "
 			"Adjusting to %d",
 			offset + length, finish - offset);
+		length = finish - offset;
 	}
 
 	memset(&req, 0, sizeof(req));
@@ -715,6 +720,7 @@
 		}
 	}
 
+	size_left_in_buffer = length;
 	do {
 		tmp = fru->access ? off >> 1 : off;
 		msg_data[0] = id;
@@ -756,9 +762,18 @@
 		}
 
 		tmp = fru->access ? rsp->data[0] << 1 : rsp->data[0];
+		if(rsp->data_len < 1
+		   || tmp > rsp->data_len - 1
+		   || tmp > size_left_in_buffer)
+		{
+			printf(" Not enough buffer size");
+			return -1;
+		}
+
 		memcpy(frubuf, rsp->data + 1, tmp);
 		off += tmp;
 		frubuf += tmp;
+		size_left_in_buffer -= tmp;
 		/* sometimes the size returned in the Info command
 		* is too large.  return 0 so higher level function
 		* still attempts to parse what was returned */
@@ -791,7 +806,9 @@
 			uint32_t offset, uint32_t length, uint8_t *frubuf)
 {
 	static uint32_t fru_data_rqst_size = 20;
-	uint32_t off = offset, tmp, finish;
+	uint32_t off = offset;
+	uint32_t tmp, finish;
+	uint32_t size_left_in_buffer;
 	struct ipmi_rs * rsp;
 	struct ipmi_rq req;
 	uint8_t msg_data[4];
@@ -804,10 +821,12 @@
 
 	finish = offset + length;
 	if (finish > fru->size) {
+		memset(frubuf + fru->size, 0, length - fru->size);
 		finish = fru->size;
 		lprintf(LOG_NOTICE, "Read FRU Area length %d too large, "
 			"Adjusting to %d",
 			offset + length, finish - offset);
+		length = finish - offset;
 	}
 
 	memset(&req, 0, sizeof(req));
@@ -822,6 +841,8 @@
 	if (fru->access && fru_data_rqst_size > 16)
 #endif
 		fru_data_rqst_size = 16;
+
+	size_left_in_buffer = length;
 	do {
 		tmp = fru->access ? off >> 1 : off;
 		msg_data[0] = id;
@@ -853,8 +874,16 @@
 		}
 
 		tmp = fru->access ? rsp->data[0] << 1 : rsp->data[0];
+		if(rsp->data_len < 1
+		   || tmp > rsp->data_len - 1
+		   || tmp > size_left_in_buffer)
+		{
+			printf(" Not enough buffer size");
+			return -1;
+		}
 		memcpy((frubuf + off)-offset, rsp->data + 1, tmp);
 		off += tmp;
+		size_left_in_buffer -= tmp;
 
 		/* sometimes the size returned in the Info command
 		* is too large.  return 0 so higher level function
```
